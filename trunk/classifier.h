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
#include "base/scoped_ptr.h"
#include "base/util.h"
#include <vector>
#include <boost/regex.hpp>

using std::string;
using std::vector;
class Connection;
class Classifier;

enum ConnectionProtocol {
  UNKNOWN = 0,
  HTTP,
  FTP,
  OTHER
};

enum ClientServerMode {
  INGRESS_IS_UNKNOWN,
  INGRESS_IS_SERVER,
  INGRESS_IS_CLIENT
};

// TODO: add comments
class ConnectionClassifier {
 public:
  // Constructs the object from the Classifier (the url classifier), and a
  // conntrack Connection.
  ConnectionClassifier(Classifier* classifier, Connection* connection);

  // Classification mark and buffer hints accesors.
  int32 classification_mark() const { return mark_; }
  int32 egress_hint() const { return egress_buffer_hint_; }
  int32 ingress_hint() const { return ingress_buffer_hint_; }

  // Updates the ConnectionClassifier status with new data added to the
  // Connection's buffers. Returns true iff the classification is definitive.
  bool update();

  // Reverses the ConnectionClassifier object, for when conntrack started using
  // the wrong ORIG & REPL directions.
  void reverse_connection();

 private:
  // Tries to guess the protocol in the two in/egress buffers.
  // Returns UNKNOWN if unknown, HTTP/FTP if http/ftp, or OTHER if the
  // connection was identified as not using in http/ftp protocol.
  ConnectionProtocol guess_protocol() const;

  // Updates the the classifier status with the latest buffer update.
  void update_ftp();
  void update_http();

  // HTTP/FTP protocol matcher internal functions.
  void http_handle_buffer(bool ingress);
  bool http_parse_request_line(const string& line,
                               string* method, string* url) const;
  bool http_parse_response_line(const string& line) const;

  // Returns the start position in the buffer for the given buffer hint.
  // Returns the real buffer length.
  uint32 egress_buffer_start() const;
  uint32 ingress_buffer_start() const;
  uint32 egress_buffer_length() const;
  uint32 ingress_buffer_length() const;

  // Links to the URL classifier, and to the local Connection.
  Classifier* classifier_;
  Connection* connection_;

  // Stores the current known protocol (if any).
  ConnectionProtocol connection_type_;

  // Buffer hints, used to reduce memory footprint in conntrack.h's Connection.
  // Also used to know up to which point the buffer was processed.
  uint32 egress_buffer_hint_;
  uint32 ingress_buffer_hint_;

  // Connection direction hint, and classifier state.
  ClientServerMode direction_hint_;

  // Last known classification mark, and definitive status.
  bool classified_;
  int32 mark_;

  DISALLOW_EVIL_CONSTRUCTORS(ConnectionClassifier);
};

// TODO: add comments
class ClassificationRule {
 public:
  // Types of URL matched by the filter.
  enum Protocol {
    HTTP,
    FTP
  };

  // Initializes a new rule for the @p protocol, with the @p mark as
  // classification mark in case of match.
  ClassificationRule(Protocol protocol, int32 mark);

  // Classification mark accessor.
  int32 mark() const { return mark_; }

  // Classification constraints mutators.
  void set_method_regex(const string& method) {
    initialize_regex(method_, method);
  }
  void set_method_plain(const string& method) {
     initialize_regex(method_, StringPrintf("^%s$", method.c_str()));
  }
  void set_url_regex(const string& url) {
     initialize_regex(url_, url);
  }
  void set_url_maxsize(int max_size) {
    if (max_size < 1) {
      LOG(FATAL, "ClassificationRule only acceps max_size urls of 1 and more.");
    }
    initialize_regex(url_, StringPrintf("^.{%d,}$", max_size + 1));
  }

  // Returns true iff the @p protocol/method/url are matching the rule's
  // constraints.
  bool match(Protocol protocol, const string& method, const string& url);

  // Returns the rule in ASCII format.
  string str() const;

 private:
  // Initialises the @p regexp with the @p text, calling LOG(FATAL) in case
  // of error.
  void initialize_regex(scoped_ptr<boost::regex>& regex, const string& text);

  // Defines the scope of the rule, and the associated mark.
  Protocol protocol_;
  int32 mark_;

  // Contraints.
  scoped_ptr<boost::regex> method_;
  scoped_ptr<boost::regex> url_;

  DISALLOW_EVIL_CONSTRUCTORS(ClassificationRule);
};

// TODO: add comments
class Classifier {
 public:
  // Special meaning classification marks.
  static const int32 kMarkUntouched = 0;
  static const int32 kNoMatchYet = 1;
  static const int32 kNoMatch = 2;

  Classifier();
  ~Classifier();

  // Rule accessor.
  const vector<ClassificationRule*>& rules() const { return rules_; }

  // Adds the @p rule to the list of classifications rules. The callee becomes
  // owner of the pointer.
  void add_rule(ClassificationRule* rule) {
    rules_.push_back(rule);
  }

  // Returns a new ConnectionClassifier object, initialized from the @p
  // Connection object. Caller becomes responsible of the object destruction.
  ConnectionClassifier* get_connection_classifier(Connection* connection) {
    return new ConnectionClassifier(this, connection);
  }

  // Returns the classification mark for the @p protocol, @p method, and @p url.
  // Returns kNoMatch if no match is found.
  int32 get_classification(ClassificationRule::Protocol protocol,
                           const string& method,
                           const string& url);

 private:
  // List of rules used for classification.
  vector<ClassificationRule*> rules_;

  DISALLOW_EVIL_CONSTRUCTORS(Classifier);
};

#endif
