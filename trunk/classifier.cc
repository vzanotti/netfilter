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

#include "base/googleinit.h"
#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "classifier.h"
#include "conntrack.h"

//
// Common regexps and helpers used for http/ftp protocol matching.
//
static const boost::regex http_request_line(
    "^([a-z]+) (.*) HTTP(/.*)?\r?$",
    boost::regex_constants::extended | boost::regex_constants::icase);
static const boost::regex http_header_line(
    "^[^ ]+: .*\r?$",
    boost::regex_constants::extended | boost::regex_constants::icase);
static const boost::regex http_response_line(
    "^HTTP(/[0-9\\.]+)? [0-9]+",
    boost::regex_constants::extended | boost::regex_constants::icase);

// Puts the line starting at @p start_pos in the @p buffer, and returns
// the next line position, or returns string::npos if no line is found.
// A line can end with any of \r and \n.
size_t get_line(const string& buffer, size_t start_pos, string* line) {
  CHECK(line != NULL);
  size_t eol_index = buffer.find_first_of("\r\n", start_pos);

  if (eol_index != string::npos) {
    line->assign(buffer.substr(start_pos, eol_index - start_pos));
    return eol_index + 1;
  }
  return string::npos;
}

// Puts the first line in the @p buffer, and returns true, or returns false
// if no line is found.
bool get_first_line(const string& buffer, string* line) {
  return get_line(buffer, 0, line) != string::npos;
}

//
// Implementation of the ConnectionClassifier class.
//
ConnectionClassifier::ConnectionClassifier(
    Classifier* classifier, Connection* connection)
  : classifier_(classifier),
    connection_(connection),
    connection_type_(UNKNOWN),
    egress_buffer_hint_(0),
    ingress_buffer_hint_(0),
    direction_hint_(INGRESS_IS_UNKNOWN),
    classified_(false),
    mark_(Classifier::kNoMatchYet) {
}

void ConnectionClassifier::reverse_connection() {
  std::swap(egress_buffer_hint_, ingress_buffer_hint_);

  if (direction_hint_ == INGRESS_IS_SERVER) {
    direction_hint_ = INGRESS_IS_CLIENT;
  } else if (direction_hint_ == INGRESS_IS_CLIENT) {
    direction_hint_ = INGRESS_IS_SERVER;
  }
}

bool ConnectionClassifier::update() {
  // If connection has already been classified, returns immediately.
  if (classified_) {
    return true;
  }

  // If connection is of unknown type, try to the the protocol.
  if (connection_type_ == UNKNOWN) {
    connection_type_ = guess_protocol();

    // If the guess_protocol() wasn't able to guess the protocol, let's have
    // a no match yet; if guess_protocol() was able identify the connection
    // is *not* an http/ftp connection, stops the classification with a NoMatch.
    if (connection_type_ == UNKNOWN) {
      mark_ = Classifier::kNoMatchYet;
    } else if (connection_type_ == OTHER) {
      mark_ = Classifier::kNoMatch;
      classified_ = true;
    }
  }

  // If the connection is of known&handled protocol, redirects to the
  // appropriate protocol handler.
  if (connection_type_ == HTTP) {
    update_http();
  } else if (connection_type_ == FTP) {
    update_ftp();
  }

  return classified_;
}

ConnectionProtocol ConnectionClassifier::guess_protocol() const {
  // Indicates whether the protocol-specific matchers were able to rule
  // negatively with enough evidences or not.
  bool enough_material = true;

  // Looks for http-specific patterns.
  if (connection_->buffer_ingress().size() > 0) {
    string line;
    if (get_line(connection_->buffer_ingress(), ingress_buffer_start(), &line)) {
      if (http_parse_request_line(line, NULL, NULL)) {
        return HTTP;
      }
      if (http_parse_response_line(line)) {
        return HTTP;
      }
    } else {
      enough_material = false;
    }
  }
  if (connection_->buffer_egress().size() > 0) {
    string line;
    if (get_line(connection_->buffer_egress(), egress_buffer_start(), &line)) {
      if (http_parse_request_line(line, NULL, NULL)) {
        return HTTP;
      }
      if (http_parse_response_line(line)) {
        return HTTP;
      }
    } else {
      enough_material = false;
    }
  }

  // Looks for ftp-specific patterns.
  // TODO: add ftp-matching logic

  if (enough_material) {
    return OTHER;
  }
  return UNKNOWN;
}

void ConnectionClassifier::update_ftp() {
  // TODO: add ftp-matching logic
}


void ConnectionClassifier::update_http() {
  // The http classifier is only using the very first line of the buffer,
  // so both the hints should be equal to 0.
  CHECK(egress_buffer_hint_ == 0);
  CHECK(ingress_buffer_hint_ == 0);

  if (ingress_buffer_length() > 0 && direction_hint_ != INGRESS_IS_SERVER) {
    http_handle_buffer(true);
  }
  if (egress_buffer_length() > 0 && direction_hint_ != INGRESS_IS_CLIENT) {
    http_handle_buffer(false);
  }
}

void ConnectionClassifier::http_handle_buffer(bool ingress) {
  const string& buffer =
      (ingress ? connection_->buffer_ingress() : connection_->buffer_egress());

  string line;
  if (get_first_line(buffer, &line)) {
    string method, url;
    if (http_parse_request_line(line, &method, &url)) {
      DLOG("HTTP found with m=%s, u=%s", method.c_str(), url.c_str());
      mark_ = classifier_->get_classification(ClassificationRule::HTTP,
                                              method, url);
      direction_hint_ = (ingress ? INGRESS_IS_CLIENT : INGRESS_IS_SERVER);
      classified_ = true;
    } else if (http_parse_response_line(line)) {
      direction_hint_ = (ingress ? INGRESS_IS_SERVER : INGRESS_IS_CLIENT);
    } else {
      DLOG("Not an HTTP connection (incriminated line: '%s').", line.c_str());
      mark_ = Classifier::kNoMatch;
      classified_ = true;
    }
  }
}

bool ConnectionClassifier::http_parse_request_line(const string& line,
                                                   string* method,
                                                   string* url) const {
  boost::smatch what;
  if (!boost::regex_match(line, what, http_request_line)) {
    return false;
  }

  if (method) {
    method->assign(what[1]);
  }
  if (url) {
    url->assign(what[2]);
  }
  return true;
}

bool ConnectionClassifier::http_parse_response_line(const string& line) const {
  return boost::regex_match(line, http_response_line);
}


uint32 ConnectionClassifier::egress_buffer_start() const {
  uint32 buffer_start = egress_buffer_hint_ -
      (connection_->bytes_egress() - connection_->buffer_egress().size());
  CHECK(buffer_start <= connection_->buffer_egress().size());
  return buffer_start;
}

uint32 ConnectionClassifier::ingress_buffer_start() const {
  uint32 buffer_start = ingress_buffer_hint_ -
      (connection_->bytes_ingress() - connection_->buffer_ingress().size());
  CHECK(buffer_start <= connection_->buffer_ingress().size());
  return buffer_start;
}

uint32 ConnectionClassifier::egress_buffer_length() const {
  return connection_->bytes_egress() - egress_buffer_hint_;
}

uint32 ConnectionClassifier::ingress_buffer_length() const {
  return connection_->bytes_ingress() - ingress_buffer_hint_;
}

//
// Implementation of the ClassificationRule class.
//
ClassificationRule::ClassificationRule(Protocol protocol, int32 mark)
  : protocol_(protocol),
    mark_(mark),
    method_(NULL),
    url_(NULL) {
  if (protocol != HTTP && protocol != FTP) {
    LOG(FATAL, "ClassificationRule only accepts HTTP and FTP as protocols.");
  }
}

void ClassificationRule::initialize_regex(scoped_ptr<boost::regex>& regex,
                                          const string& text) {
  regex.reset(new boost::regex(
      text,
      boost::regex_constants::extended |
          boost::regex_constants::icase |
          boost::regex_constants::no_except));
  if (regex->status() != 0) {
    LOG(FATAL, "String '%s' is not a valid regular expression.", text.c_str());
  }
}

bool ClassificationRule::match(Protocol protocol,
                               const string& method,
                               const string& url) {
  return (protocol_ == protocol) &&
      (!method_.get() || boost::regex_match(method, *method_)) &&
      (!url_.get() || boost::regex_match(url, *url_));
}

string ClassificationRule::str() const {
  string rule = StringPrintf("mark=%d proto=%s",
                             mark_,
                             protocol_ == HTTP ? "http" : "ftp");
  if (url_.get()) {
    rule.append(" url=");
    rule.append(url_->str());
  }
  if (method_.get()) {
    rule.append(" method=");
    rule.append(method_->str());
  }

  return rule;
}

//
// Implementation of the Classifier class.
//
Classifier::Classifier() {
}

Classifier::~Classifier() {
  for (vector<ClassificationRule*>::iterator it = rules_.begin();
       it != rules_.end(); ++it) {
    delete *it;
  }
  rules_.clear();
}

int32 Classifier::get_classification(ClassificationRule::Protocol protocol,
                                     const string& method,
                                     const string& url) {
  for (vector<ClassificationRule*>::const_iterator it = rules_.begin();
       it != rules_.end(); ++it) {
    if ((*it)->match(protocol, method, url)) {
      return (*it)->mark();
    }
  }

  return kNoMatch;
}
