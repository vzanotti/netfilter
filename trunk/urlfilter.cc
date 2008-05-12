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
#include "classifier.h"
#include "conntrack.h"
#include "queue.h"
#include <pthread.h>
#include <signal.h>
#include <google/gflags.h>

DEFINE_int32(queue, 0,
             "No. of the NFQUEUE to listen to for packets to classify.");
DEFINE_int32(mark_mask, 0xffff,
             "Mask to use when adding the classification information to the "
             "NFQUEUE mark.");
// TODO: add parameters for the classification configuration.

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

int main(int argc, char** argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);

  // TODO: configure a classifier, and pass it as a ConnTrack construction-time
  // argument.
  Classifier classifier;

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
