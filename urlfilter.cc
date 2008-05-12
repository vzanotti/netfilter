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

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/io.h"
#include "classifier.h"
#include "conntrack.h"
#include "queue.h"
#include <map>
#include <pthread.h>
#include <signal.h>
#include <boost/regex.h>
#include <google/gflags.h>

using std::map;

DEFINE_int32(queue, 0,
             "No. of the NFQUEUE to listen to for packets to classify.");
DEFINE_int32(mark_mask, 0xffff,
             "Mask to use when adding the classification information to the "
             "NFQUEUE mark.");
DEFINE_string(rules, "",
              "File containing the urlfilter rules. They are supposed to be in "
              "the 'mark=<mark> proto=<proto> url=<url regex> method=<method>' "
              "format (alternatively, method_re and url_maxsize can be used). "
              "Regexps are standard unix regexpes.");

// Starts the conntrack management thread. Returns the thread id.
void* conntrack_thread_starter(void* data) {
  reinterpret_cast<ConnTrack*>(data)->Run();
  LOG(INFO, "Conntrack thread is exiting.");
  pthread_exit(NULL);
}
pthread_t start_conntrack_thread(ConnTrack* conntrack) {

  pthread_t thread_id;
  if (pthread_create(&thread_id, 0, conntrack_thread_starter, conntrack) < 0) {
    LOG(FATAL, "Could not start the conntrack thread (%s).", strerror(errno));
  }

  return thread_id;
}

// Starts the queue listener & packet processor. Returns the thread id.
void* queuehandler_thread_starter(void* data) {
  reinterpret_cast<Queue*>(data)->Run();
  LOG(INFO, "Queue thread is exiting.");
  pthread_exit(NULL);
}
pthread_t start_queuehandler_thread(Queue* queue) {
  pthread_t thread_id;
  if (pthread_create(&thread_id, 0, queuehandler_thread_starter, queue) < 0) {
    LOG(FATAL, "Could not start the queue thread (%s).", strerror(errno));
  }

  return thread_id;
}

// Sets up a signal handler to gracefully stop the urlfilter on SIGQUIT/SIGINT.
ConnTrack* __signal_handler_conntrack = NULL;
Queue* __signal_handler_queue = NULL;
void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGQUIT) {
    LOG(INFO, "Received signal %s, stopping.",
        (signum == SIGINT ? "SIGINT" : "SIGQUIT"));

    if (__signal_handler_conntrack) {
      __signal_handler_conntrack->Stop();
    }
    if (__signal_handler_queue) {
      __signal_handler_queue->Stop();
    }

    // Restores the signal handler to its default value, so as to make sure
    // a second SIGINT/SIGQUIT signal will be effective.
    signal(signum, SIG_DFL);
  }
}

void setup_signal_handler(ConnTrack* conntrack, Queue* queue) {
  __signal_handler_conntrack = conntrack;
  __signal_handler_queue = queue;
  signal(SIGINT, &signal_handler);
  signal(SIGQUIT, &signal_handler);
}

// Loads the classification rules from a file, parse them, and imports
// them in the @p classifier.
void load_rules(File* rules, Classifier* classifier) {
  int nrules = 0, nline = 1;
  boost::regex proto_ftp("^ftp$", boost::regex_constants::icase);
  boost::regex proto_http("^http$", boost::regex_constants::icase);
  
  string line;
  for (; rules->ReadLine(&line); nline++) {
    if (line.size() < 2 || line[0] == '#') {
      continue;
    }

    vector<pair<string, string> > rule_kv;
    SplitStringIntoKeyValuePairs(line, "=", " \t", &rule_kv);
    map<string, string> rule_map(rule_kv.begin(), rule_kv.end());
    
    if (rule_map.find("mark") == rule_map.end() ||
        rule_map.find("proto") == rule_map.end()) {
      LOG(INFO, "At line %d:", nline);
      LOG(FATAL, "An urlfilter rule must include at least a mark and a proto.");
    }
    
    int32 mark = strtol(rule_map["mark"].c_str(), NULL, 10);
    ClassificationRule::Protocol proto = ClassificationRule::Protocol(-1);
    if (regex_match(rule_map["proto"], proto_ftp)) {
      proto = ClassificationRule::FTP;
    } else if (regex_match(rule_map["proto"], proto_http)) {
      proto = ClassificationRule::HTTP;
    } else {
      LOG(INFO, "At line %d:", nline);
      LOG(FATAL, "Unrecognized protocol '%s'", rule_map["proto"].c_str());
    }
    ClassificationRule* rule = new ClassificationRule(proto, mark);
    
    if (rule_map.find("method") != rule_map.end()) {
      rule->set_method_plain(rule_map["method"]);
    }
    if (rule_map.find("method_re") != rule_map.end()) {
      rule->set_method_regex(rule_map["method_re"]);
    }
    if (rule_map.find("url") != rule_map.end()) {
      rule->set_url_regex(rule_map["url"]);
    }
    if (rule_map.find("url_maxsize") != rule_map.end()) {
      int max_size = strtol(rule_map["url_maxsize"].c_str(), NULL, 10);
      rule->set_url_maxsize(max_size);
    }
                                                
    nrules++;
    classifier->add_rule(rule);
  }
  
  LOG(INFO, "Loaded %d rules into the classifier:", nrules);
  for (uint r = 0; r < classifier->rules().size(); ++r) {
    LOG(INFO, "  (%d) %s", r, classifier->rules()[r]->str().c_str());
  }
}

int main(int argc, char** argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);

  // Loads the rules into a new classifier.
  Classifier classifier;
  if (FLAGS_rules.empty()) {
    LOG(FATAL, "You must specificy a rule file with --rules.");
  }
  
  scoped_ptr<File> rules(File::OpenOrDie(FLAGS_rules.c_str(), "r"));
  load_rules(rules.get(), &classifier);

  // Prepares and starts the conntrack thread.
  ConnTrack conntrack(&classifier);
  pthread_t conntrack_thread = start_conntrack_thread(&conntrack);

  // Prepares and starts the queue thread.
  Queue queue(FLAGS_queue, FLAGS_mark_mask, &conntrack);
  pthread_t queue_thread = start_queuehandler_thread(&queue);

  // Sets up the signals handler.
  setup_signal_handler(&conntrack, &queue);

  // Waits for the two threads to terminate.
  pthread_join(conntrack_thread, NULL);
  pthread_join(queue_thread, NULL);
}
