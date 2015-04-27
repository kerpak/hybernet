/**
 * @file
 *
 * Distributed under the Boost Software License, Version 1.0.
 * See accompanying file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt
 */

#ifndef __HYBERNET_SESSION_HPP__
#define __HYBERNET_SESSION_HPP__

#ifndef SWIG
#include <memory>
#include <string>
#include <vector>
#endif

namespace hybernet {

struct session {
  session();
  ~session();

  std::vector<std::string> get_peers();

  std::string get_name(std::string hash);
  std::string get_thumbnail(std::string hash);
  std::string get_description(std::string hash);

  void publish(std::string message);

private:
  struct impl;
  std::unique_ptr<impl> pimpl;
};

}

#endif // ifndef __HYBERNET_SESSION_HPP__
