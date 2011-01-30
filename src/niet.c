#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>

#define LOGGER_COMMAND "logger"
#define RESPAWN_CYCLE 60
#define DEBUG_AT_CONSOLE

int close_on_exec(int fileno) {
	int result = fcntl(fileno, F_GETFD, 0);
	if (result < 0) return result;
	return fcntl(fileno, F_SETFD, result | FD_CLOEXEC);
}

int pipe_to_logger(char* const log_priority, char* const log_tag, int fileno, sigset_t* blocked_signals) {
	int result;
	int pipe_handles[2];
	pid_t child;
	
	// create a pipe to talk to the child logger process over
	if (pipe(pipe_handles) < 0) {
		perror("Couldn't create a pipe");
		return -1;
	}
	
	// fork to give us a new process to run the logger
	child = fork();
	if (child < 0) {
		// hit the process limit
		close(pipe_handles[0]);
		close(pipe_handles[1]);
		perror("Couldn't fork to start logger");
		return -1;
		
	} else if (child == 0) {
		// we are the child; we're meant to run logger, which only needs stdin and produces (hopefully) no output.
		
		// the logger shouldn't ever output itself, and it really should close stdout and stderr after it starts 
		// up successfully.  but at least some common implementations don't, and we don't want loggers to hold
		// open pipes to previous loggers, since then we'd end up with a linked list of logger processes which
		// wouldn't go away until the last one has its inputs closed.  we don't want to close our output just yet
		// though, because we want somewhere to complain to if our execvp call fails, so instead we turn on the
		// close-on-exec flag for them.  the logger processes themselves still have nowhere to complain to, but
		// that's unavoidable - where could they send it?
		close_on_exec(STDOUT_FILENO); // ignore errors if these have already been closed
		close_on_exec(STDERR_FILENO);
		
		do { result = dup2(pipe_handles[0], STDIN_FILENO); } while (result < 0 && errno == EINTR); // closes STDIN_FILENO
		if (result < 0) {
			perror("Couldn't attach the pipe to the logger input");
			return -1;
		}
		
		close(pipe_handles[0]); // now it's been dupd, we don't need the allocated descriptor
		close(pipe_handles[1]); // and we won't write into the pipe, and want to notice when the actual writer closes it

		// execute the logger program, replacing this program
		char* arguments[] = {LOGGER_COMMAND, "-p", log_priority, "-t", log_tag, NULL};
		sigprocmask(SIG_UNBLOCK, blocked_signals, NULL);
		execvp(LOGGER_COMMAND, arguments); // only returns if there's an error
		perror("Couldn't execute logger");
		return -1;
		
	} else {
		// we are the parent; we can write to pipe_handles[1], and it'll go to the child logger process
		do { result = dup2(pipe_handles[1], fileno); } while (result < 0 && errno == EINTR); // closes the original fileno, if it's currently open
		if (result < 0) {
			perror("Couldn't attach the pipe to the logger output");
			return -1;
		}

		close(pipe_handles[1]); // now it's been dupd, we don't need the allocated descriptor
		close(pipe_handles[0]); // and we won't read from the pipe
		return 0;
	}
}

void dummy_handler(int signo) {
	// do nothing
}

int install_signal_handler(int signo, void (*func)(int)) {
	struct sigaction action;
	action.sa_handler = func;
	action.sa_flags = 0; // no SA_RESTART (apparently on by default on some OSs)
	if (sigemptyset(&action.sa_mask) < 0 ||
		sigaction(signo, &action, NULL) < 0) {
		return -1;
	}
	return 0;
}

int install_signal_handlers(sigset_t* signals) {
	// we'll use sigwait to wait for any of the signals of interest to be delivered, since some of
	// the actions we want to take can't be taken inside a signal handler (ie. non-async-signal-safe
	// syscalls).  however, sigwait will only return for signals that were not ignored (since the OS
	// drops ignored signals early), so we set some handlers even though the handlers do nothing.
	if (install_signal_handler(SIGQUIT, &dummy_handler) < 0 ||
	    install_signal_handler(SIGTERM, &dummy_handler) < 0 ||
	    install_signal_handler(SIGCHLD, &dummy_handler) < 0 ||
	    install_signal_handler(SIGALRM, &dummy_handler) < 0 ||
	    install_signal_handler(SIGUSR1, &dummy_handler) < 0 ||
	    install_signal_handler(SIGUSR2, &dummy_handler) < 0 ||
	    install_signal_handler(SIGHUP,  &dummy_handler) < 0) {
		perror("Couldn't install signal handler");
		return -1;
	}

	if (sigemptyset(signals) < 0 ||
	    sigaddset(signals, SIGQUIT) < 0 ||
	    sigaddset(signals, SIGTERM) < 0 ||
	    sigaddset(signals, SIGCHLD) < 0 ||
	    sigaddset(signals, SIGALRM) < 0 ||
	    sigaddset(signals, SIGUSR1) < 0 ||
	    sigaddset(signals, SIGUSR2) < 0 ||
	    sigaddset(signals, SIGHUP)  < 0 ||
		sigprocmask(SIG_BLOCK, signals, NULL) < 0) {
		perror("Couldn't establish blocked signal set");
		return -1;
	}
	
	return 0;
}

void clear_pending_blocked_signals(int signo) {
	install_signal_handler(signo, signal(signo, SIG_IGN));
}

/**
 * Clears the alarm timer, clears any pending alarms (alarms that have timed out but whose signal
 * is currently blocked by the sigprocmask), and then if seconds is >0, starts the alarm timer.
 */
void reset_alarm(unsigned int seconds) {
	alarm(0);
	clear_pending_blocked_signals(SIGALRM);
	alarm(seconds);
}

int main(int argc, char* argv[]){
	int respawn = 1;
	sigset_t signals;
	
	char* log_tag = argv[1];
	char* stdout_pri = argv[2];
	char* stderr_pri = argv[3];
	char** program_arguments = argv + 4;
	
	if (argc < 5) {
		fprintf(stderr, "%s",
			"Usage: niet someprogram user.info user.err /usr/bin/someprogram\n" \
		    " - runs /usr/bin/someprogram, piping its stdout to a logger with priority\n" \
		    "   user.info and tag someprogram, and piping its stderr to a logger with\n" \
		    "   priority user.err and tag someprogram.  restarts someprogram if it dies,\n" \
			"   waiting for up to %ds if it's dying quickly.\n", RESPAWN_CYCLE);
		return 100;
	}
	
	// detach from the terminal and the calling shell (if any)
	#ifndef DEBUG_AT_CONSOLE
	if (fork() != 0) return;
	setsid();
	close(STDIN_FILENO);
	chdir("/");
	#endif
	umask(0);
	
	if (install_signal_handlers(&signals) < 0) {
		return 6;
	}

	// we'll be reattaching stdout and stderr to go to logger processes, so we don't want file-style output buffering
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	
	while (respawn) {
		time_t start_time, end_time;
		pid_t child;

		if (pipe_to_logger(stdout_pri, log_tag, STDOUT_FILENO, &signals) < 0) return 1;
		if (pipe_to_logger(stderr_pri, log_tag, STDERR_FILENO, &signals) < 0) return 2;
		
		// so we're the parent process, and our stdout now goes to one logger process's stdin, and
		// our stderr now goes to a second logger process's stdin.
		fprintf(stdout, "Running %s\n", program_arguments[0]);
		start_time = time(NULL);
		child = fork();
		if (child < 0) {
			perror("Couldn't fork to start program");
			return 3;
			
		} else if (child == 0) {
			// we are the child; run the target program
			sigprocmask(SIG_UNBLOCK, &signals, NULL);
			execvp(program_arguments[0], program_arguments); // argv[argc] is required to be 0, so fine to pass to execvp
			perror("Couldn't execute program");
			return 4;
			
		} else {
			// we are the parent; wait for a TERM signal or a CHLD signal when the child exits
			int signo;
			int terminated = 0;
			while (child) {
				if (sigwait(&signals, &signo) < 0) {
					perror("Failed to wait on signals");
					return 5;
				}

				switch (signo) {
					case SIGCHLD:
						// non-realtime signals coalesce, so we can be delivered one SIGCHLD even if several
						// child processes have terminated (eg. loggers plus the child program of interest),
						// so we need to repeatedly call waitpid before waiting for another signal
						while (1) {
							int status;
							int result = waitpid(-1, &status, WNOHANG);
							if (result == child) {
								// the child has terminated and we've cleaned up the child handle; log what happened
								if (WIFEXITED(status)) {
									if (WEXITSTATUS(status) != 0) {
										fprintf(stderr, "%s exited with status %d\n", program_arguments[0], WEXITSTATUS(status));
									} else if (terminated) {
										fprintf(stdout, "%s finished as requested\n", program_arguments[0]);
									} else {
										fprintf(stdout, "%s finished\n", program_arguments[0]);
									}
								} else if (WTERMSIG(status) == SIGTERM && terminated) {
									fprintf(stdout, "%s terminated as requested\n", program_arguments[0]);
								} else {
									fprintf(stderr, "%s was terminated by signal %d\n", program_arguments[0], WTERMSIG(status));
								}
								child = 0; // break out of the sigwait loop
								break;
							} else if (result <= 0) {
								// no more terminated child processes
								break;
							}
						}
						break;

					case SIGTERM:
						// we were sent a TERM, send one to the child process and then respawn it
						fprintf(stdout, "Asking %s to terminate so we can restart it\n", program_arguments[0]);
						kill(child, SIGTERM); // ignore errors from sending to zombies	
						terminated = 1;
						// keep respawning
						break;

					case SIGQUIT:
						// we were sent a QUIT, send a TERM to the child process and then quit
						fprintf(stdout, "Asking %s to terminate so we can shut down\n", program_arguments[0]);
						kill(child, SIGTERM); // ignore errors from sending to zombies
						terminated = 1;
						respawn = 0;
						break;
					
					case SIGUSR1:
					case SIGUSR2:
					case SIGHUP:
						fprintf(stdout, "Passing the %s signal on to %s\n", strsignal(signo), program_arguments[0]);
						kill(child, signo); // ignore errors from sending to zombies
						break;
				
					default:
						fprintf(stderr, "Unexpected signal %d\n", signo);
				}
			}

			// if the child exited in t < 60 seconds, wait 60-t seconds before starting it again
			end_time = time(NULL);
			if (!terminated && // we don't do the wait if we were manually told to stop or restart the program
				end_time >= start_time && // should generally always be true, but clocks can be reset...
				end_time < start_time + RESPAWN_CYCLE) {
				// we use signals rather than a plain sleep call because we want to terminate promptly if sent QUIT (note we have signals blocked)
				// we would use sigtimedwait, but OS X doesn't have it (despite having sigwait); instead, we use the alarm signal
				int seconds = RESPAWN_CYCLE - (end_time - start_time);
				reset_alarm(seconds);
				fprintf(stdout, "Waiting %ds before respawning %s\n", seconds, program_arguments[0]);
				while (1) {
					sigwait(&signals, &signo); // wake up when the alarm timer runs out or a TERM or QUIT is received
		
					if (signo == SIGCHLD) {
						while (waitpid(-1, NULL, WNOHANG) <= 0) ; // cleanup but otherwise ignore terminating loggers, and keep waiting

					} else if (signo == SIGQUIT) {
						respawn = 0; // when sent QUIT we want to terminate ourselves, as for signals sent while the child is running
						break;
						
					} else if (signo == SIGTERM || signo == SIGALRM) {
						break; // stop waiting and get on with restarting
					}
					// ignore usr1, usr2, and hup, as we have no child process to pass them on to
				}
				reset_alarm(0);
			}
		}
	}
	fprintf(stdout, "Shut down by request.\n");
	return 0;
}
