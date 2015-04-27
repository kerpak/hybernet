#include "session.hpp"

#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <sstream>

#include <libtorrent/alert_types.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/bencode.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/upnp.hpp>
#include <libtorrent/natpmp.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/peer_info.hpp>

#include <sodium/crypto_sign_ed25519.h>

#include <zmq.hpp>

namespace hybernet {
namespace torr = ::libtorrent;

struct session::impl {
  std::string public_key;
  std::string secret_key;
  std::string state;

  torr::session sess;

  bool        terminated;
  std::thread worker;
  std::thread workerz;

  impl() {
    {
      std::ifstream inpk {"state.pk", std::ios_base::binary};
      std::ifstream insk {"state.sk", std::ios_base::binary};

      if (inpk.good() && insk.good()) {
        public_key.resize(crypto_sign_ed25519_PUBLICKEYBYTES);
        public_key.resize(inpk.readsome(&public_key[0], public_key.size()));

        secret_key.resize(crypto_sign_ed25519_SECRETKEYBYTES);
        secret_key.resize(insk.readsome(&secret_key[0], secret_key.size()));
      }

      if (public_key.size() != crypto_sign_ed25519_PUBLICKEYBYTES ||
          secret_key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        public_key.resize(crypto_sign_ed25519_PUBLICKEYBYTES);
        secret_key.resize(crypto_sign_ed25519_SECRETKEYBYTES);
        crypto_sign_ed25519_keypair(reinterpret_cast<uint8_t*>(&public_key[0]), reinterpret_cast<uint8_t*>(&secret_key[0]));
      }
    }

    {
      std::ifstream inp {"state.dat", std::ios_base::binary};

      if (inp.good()) {
        std::copy(std::istream_iterator<char>(inp), std::istream_iterator<char>(), std::back_inserter(state));

        torr::error_code ec;
        torr::lazy_entry ent;
        torr::lazy_bdecode(&state[0], &state[0]+state.size(), ent, ec);
        if (ec) throw torr::libtorrent_exception(ec);
        sess.load_state(ent);
      }
    }

    sess.set_alert_mask(torr::alert::all_categories ^ torr::alert::port_mapping_notification);

    sess.add_dht_router(std::make_pair("router.utorrent.com", 6881));
    sess.add_dht_router(std::make_pair("router.bittorrent.com", 6881));

    torr::error_code ec;
    sess.listen_on(std::make_pair(10581, 10589), ec);
    if (ec) throw torr::libtorrent_exception(ec);

    sess.start_dht();
    sess.start_lsd();
    sess.start_upnp();
    sess.start_natpmp();

    torr::entry self;
    self["name"] = "user-" + torr::to_hex(public_key);
    self["description"] = "";
    self["thumbnail"] = "";
    self["public_key"] = torr::to_hex(public_key);

    auto info = make_metadata(self);
    sess.set_peer_id(info.info_hash());

    {
      auto atp = torr::add_torrent_params{};
      atp.ti = new torr::torrent_info(info);
      sess.add_torrent(atp);
    }

    {
      auto atp = torr::add_torrent_params{};
      atp.info_hash = torr::sha1_hash::max();
      sess.add_torrent(atp);
    }

    terminated = false;
    worker = std::thread([&]() { while(!terminated) { check_alerts(); } });
    workerz = std::thread([&]() { while(!terminated) { monitorz(); } });
  }

/*
  torr::sha1_hash dht_put(std::string value) {
    torr::entry const en = value;
    return sess.dht_put_item(en);
  }

  void dht_put_mutable(std::string key, std::string value) {
    boost::array<char, 32> pk_array = {};
    std::memcpy(&pk_array[0], &public_key[0], 32);

    auto const put_cb = [&,value=std::move(value)](auto ent, auto sig, auto seq, auto key) {
      ent  = torr::entry(std::move(value));
      seq += 1;
      torr::dht::sign_mutable_item(std::make_pair(public_key.data(), public_key.size()),
                                   std::make_pair(key.data(), key.size()),
                                   seq,
                                   public_key.data(),
                                   secret_key.data(),
                                   &sig[0]);
    };

    sess.dht_put_item(pk_array, put_cb, key);
  }
*/

  ~impl() {
    {
      torr::entry ent;
      sess.save_state(ent);

      std::ofstream out {"state.dat", std::ios_base::binary};
      torr::bencode(std::ostream_iterator<char>(out), ent);
    }

    {
      std::ofstream out {"state.pk", std::ios_base::binary};
      out.write(reinterpret_cast<char const*>(public_key.data()), public_key.size());
    }

    {
      std::ofstream out {"state.sk", std::ios_base::binary};
      out.write(reinterpret_cast<char const*>(secret_key.data()), secret_key.size());
    }

    terminated = true;
    workerz.join();
    worker.join();
  }



  zmq::context_t zctx = zmq::context_t(1);
  zmq::socket_t  zpub = zmq::socket_t(zctx, ZMQ_PUB);
  zmq::socket_t  zsub = zmq::socket_t(zctx, ZMQ_SUB);
  uint64_t       zseq = 0;

  std::vector<std::function<void(void)>> actionz;
  std::mutex                             actionz_mutex;

  std::unordered_set<std::string>        zsha1s_set;
  std::deque<std::string>                zsha1s_list;

  void monitorz() {
    std::vector<std::function<void(void)>> actz;

    {
      std::lock_guard<std::mutex> _(actionz_mutex);
      std::move(std::begin(actionz), std::end(actionz), std::back_inserter(actz));
      actionz.clear();
    }

    for (auto const& a : actz)
      a();

    auto msgz = zmq::message_t{};
    if (zsub.recv(&msgz, ZMQ_NOBLOCK)) {
      auto const sha1 = std::string(static_cast<char const*>(msgz.data()), msgz.size());

      uint64_t ttl = 0;
      zsub.recv(&msgz);
      std::memcpy(&ttl, msgz.data(), sizeof(ttl));

      zsub.recv(&msgz);
      auto message = std::string(static_cast<char const*>(msgz.data()), msgz.size());

      if (zsha1s_set.find(sha1) != zsha1s_set.end())
        return;

      if (zsha1s_list.size() > 1000) {
        zsha1s_set.erase(zsha1s_list.front());
        zsha1s_list.pop_front();
      }

      zsha1s_set.insert(sha1);
      zsha1s_list.emplace_back(sha1);

      if (ttl > 0)
        sendz(std::move(sha1), ttl-1, std::move(message));
    } else {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }

  void sendz(std::string sha1, uint64_t ttl, std::string msg) {
    if (zsha1s_set.find(sha1) != zsha1s_set.end())
      return;

    zsha1s_set.insert(sha1);
    zsha1s_list.emplace_back(sha1);

    {
      auto msgz = zmq::message_t{sha1.size()};
      std::memcpy(msgz.data(), sha1.data(), sha1.size());
      zpub.send(msgz, ZMQ_SNDMORE);
    }

    {
      auto msgz = zmq::message_t{ sizeof(ttl) };
      std::memcpy(msgz.data(), &ttl, sizeof(ttl));
      zpub.send(msgz, ZMQ_SNDMORE);
    }

    {
      auto msgz = zmq::message_t{ msg.size() };
      std::memcpy(msgz.data(), msg.data(), msg.size());
      zpub.send(msgz);
    }
  }

  void pushz(auto&& a) {
    std::lock_guard<std::mutex> _(actionz_mutex);
    actionz.emplace_back(std::move(a));
  }





  std::unordered_map<std::string, torr::entry> objects;
  std::mutex                                   objects_mutex;

  void queue_object(std::string sha1) {
    if (objects.find(sha1) != objects.end())
      return;

    auto th = sess.find_torrent(torr::sha1_hash(sha1));
    if (th.is_valid()) {
      // th.force_dht_announce();
      return;
    }

    torr::add_torrent_params ps;
    ps.info_hash = torr::sha1_hash(std::move(sha1));
    sess.add_torrent(ps);
  }



  void check_alerts() {
    auto alert = sess.wait_for_alert(torr::seconds(1));

    if (alert) {
      // std::cerr << alert->message() << std::endl;

      switch (alert->type()) {
        case torr::listen_succeeded_alert::alert_type: {
          auto const& a = *static_cast<torr::listen_succeeded_alert const*>(alert);

//          if (a.sock_type != torr::listen_succeeded_alert::tcp)
//            break;

          if (a.endpoint.address().is_v4()) {
            auto endp = a.endpoint;
            endp.port(endp.port() + 100);

            std::stringstream out;
            out << "tcp://" << endp;

            auto str = out.str();
            pushz([&,str=std::move(str)]() {
              std::cerr << "binding to " << str << std::endl;
              zpub.bind(str.c_str());
            });
          }

          break;
        }

        case torr::peer_connect_alert::alert_type: {
          auto const& a = *static_cast<torr::peer_connect_alert const*>(alert);

          if (a.ip.address().is_v4()) {
            auto endp = a.ip;
            endp.port(endp.port() + 100);

            std::stringstream out;
            out << "tcp://" << endp;

            auto str = out.str();
            pushz([&,str=std::move(str)]() {
              std::cerr << "connecting to " << str << std::endl;
              zsub.connect(str.c_str());
              zsub.setsockopt(ZMQ_SUBSCRIBE, nullptr, 0);
            });
          }

          if (a.pid == torr::sha1_hash())
            break;

          std::lock_guard<std::mutex> _(objects_mutex);
          queue_object(a.pid.to_string());
          break;
        }

        case torr::peer_disconnected_alert::alert_type: {
          auto const& a = *static_cast<torr::peer_disconnected_alert const*>(alert);

          if (a.ip.address().is_v4()) {
            auto endp = a.ip;
            endp.port(endp.port() + 100);

            std::stringstream out;
            out << "tcp://" << endp;

            auto str = out.str();
            pushz([&,str=std::move(str)]() {
              std::cerr << "disconnecting from " << str << std::endl;
              try { zsub.disconnect(str.c_str()); }
              catch (zmq::error_t const&) {}
            });
          }

          if (a.pid == torr::sha1_hash())
            break;

/*
          std::lock_guard<std::mutex> _(objects_mutex);
          objects.erase(a.pid.to_string());

          auto th = sess.find_torrent(a.pid);
          if (!th.is_valid())
            break;

          sess.remove_torrent(th, torr::session::delete_files);
*/
          break;
        }

        case torr::metadata_received_alert::alert_type: {
          auto const& a = *static_cast<torr::metadata_received_alert const*>(alert);
          if (!a.handle.is_valid())
            break;

          // auto ti = *a.handle.torrent_file();
          auto ti = a.handle.get_torrent_info();
          auto meta = ti.metadata();
          auto entry = torr::bdecode(meta.get(), meta.get()+ti.metadata_size());

          std::lock_guard<std::mutex> _(objects_mutex);
          objects[ti.info_hash().to_string()] = entry;
          break;
        }
      }

      sess.pop_alert();
    }
  }

  torr::torrent_info make_metadata(torr::entry info) {
    torr::entry en;
    en["info"] = info;
    en["info"]["length"] = 1;
    en["info"]["piece length"] = 16384;
    en["info"]["pieces"] = torr::sha1_hash::min().to_string();

    std::string be;
    torr::bencode(std::back_inserter(be), en);

    torr::error_code ec;
    torr::lazy_entry lz;
    torr::lazy_bdecode(&be[0], &be[0]+be.size(), lz, ec);

    return torr::torrent_info {lz, ec};
  }




  std::vector<std::string> get_peers() {
    std::vector<std::string> out;

    auto th = sess.find_torrent(torr::sha1_hash::max());
    if (!th.is_valid())
      return out;

    //th.force_dht_announce();

    std::vector<torr::peer_info> pis;
    th.get_peer_info(pis);

    std::unordered_set<std::string> sha1s;
    std::transform(std::make_move_iterator(std::begin(pis)), std::make_move_iterator(std::end(pis)),
                   std::inserter(sha1s, sha1s.end()), [](auto&& pi) { return pi.pid.to_string(); });
    sha1s.erase(torr::sha1_hash().to_string());

    { std::lock_guard<std::mutex> _(objects_mutex);
      for (auto sha1 : sha1s)
        queue_object(sha1);
    }

    std::transform(std::begin(sha1s), std::end(sha1s), std::back_inserter(out), [](auto&& str) { return torr::to_hex(str); });
    return out;
  }

  std::string get_name(std::string hash) {
    auto sha1 = std::string((hash.size()+1)/2, 0);
    torr::from_hex(&hash[0], hash.size(), &sha1[0]);

    std::lock_guard<std::mutex> _(objects_mutex);
    auto it = objects.find(sha1);
    if (it != objects.end())
      return it->second["name"].string();

    queue_object(sha1);
    return hash;
  }

  std::string get_thumbnail(std::string hash) {
    auto sha1 = std::string((hash.size()+1)/2, 0);
    torr::from_hex(&hash[0], hash.size(), &sha1[0]);

    std::lock_guard<std::mutex> _(objects_mutex);
    auto it = objects.find(sha1);
    if (it != objects.end())
      return it->second["thumbnail"].string();

    queue_object(sha1);
    return hash;
  }

  std::string get_description(std::string hash) {
    auto sha1 = std::string((hash.size()+1)/2, 0);
    torr::from_hex(&hash[0], hash.size(), &sha1[0]);

    std::lock_guard<std::mutex> _(objects_mutex);
    auto it = objects.find(sha1);
    if (it != objects.end())
      return it->second["description"].string();

    queue_object(sha1);
    return hash;
  }

  void publish(std::string msg) {
    pushz([&,msg=std::move(msg)]() {
      torr::hasher hasher(reinterpret_cast<char const*>(&sess.id()[0]), 20);
      hasher.update(reinterpret_cast<char const*>(&zseq), sizeof(zseq));

      sendz(hasher.final().to_string(), 32, msg);
      zseq++;
    });
  }
};

session::session() : pimpl{std::make_unique<impl>()} {}
session::~session() {}

std::vector<std::string> session::get_peers() { return pimpl->get_peers(); }

std::string session::get_name(std::string hash) { return pimpl->get_name(std::move(hash)); }
std::string session::get_thumbnail(std::string hash) { return pimpl->get_thumbnail(std::move(hash)); }
std::string session::get_description(std::string hash) { return pimpl->get_description(std::move(hash)); }

void session::publish(std::string message) { return pimpl->publish(std::move(message)); }

}
