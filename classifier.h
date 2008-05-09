// Copyright 2008, Stephane Jacob <stephane.jacob@m4x.org>
// Copyright 2008, John Whitbeck <john.whitbeck@m4x.org>
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

#ifndef CLASSIFIER_H__
#define CLASSIFIER_H__

#include "base/basictypes.h"

// TODO: add comments
class Classifier {
 public:
  // Special meaning classification marks.
  static const int32 kMarkUntouched = 0;
  static const int32 kNoMatchYet = 1;
  static const int32 kNoMatch = 2;

  // TODO: write a classifier !
};

#endif
