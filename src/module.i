%module Module;
%include "std_string.i"
%include "std_vector.i"

namespace std {
  %template(StringVector) vector<string>;
};

%rename("%(camelcase)s") "";
#include "session.hpp"

%{
#include "session.hpp"
%}
