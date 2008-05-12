// Copyright 2008, Vincent Zanotti <vincent.zanotti@m4x.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef BASE_HASH_MAP_H__
#define BASE_HASH_MAP_H__

#include <string>
#include <ext/hash_fun.h>
#include <ext/hash_map>

// Imports the SGI's ext/hash_map into the STL standard namespace.
namespace std {
  using __gnu_cxx::hash_map;
}

// Specialiases the __gnu_cxx::hash for strings.
namespace __gnu_cxx {
  template<> struct hash<std::string> {
    size_t operator()(const std::string& __s) const {
      return hash<char*>()(__s.c_str());
    }
  };
}

#endif  // BASE_HASH_MAP_H__
