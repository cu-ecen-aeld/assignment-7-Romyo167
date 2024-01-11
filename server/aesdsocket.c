/*
 ** server.c -- a stream socket server demo
 */
#include <time.h>

#include <stdio.h>

#include <stdlib.h>

#include <unistd.h>

#include <errno.h>

#include <string.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>

#include <arpa/inet.h>

#include <sys/wait.h>

#include <signal.h>

#include <syslog.h>

#include <time.h>
#include <sys/queue.h>
#include <pthread.h>

struct entry
{
    pthread_t value;
    int* completeflag;
    LIST_ENTRY(entry) entries;
};


#define PORT "9000" // the port users will be connecting to

#define BACKLOG 10 // how many pending connections queue will hold
pthread_mutex_t lock; 
void sigchld_handler(int s) {
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void * get_in_addr(struct sockaddr * sa) {
    if (sa -> sa_family == AF_INET) {
        return & (((struct sockaddr_in * ) sa) -> sin_addr);
    }

    return & (((struct sockaddr_in6 * ) sa) -> sin6_addr);
}

typedef struct {
    //Or whatever information that you need
    int new_fd;
}threadparams;

void *myThreadFun(threadparams * args) {   

        FILE * msgfile = fopen("/var/tmp/aesdsocketdata", "a+");
        if (msgfile == NULL) {
            syslog(LOG_ERR, "couldn't open file for writing");
            return -1;
        }

        char * buf = (char * ) malloc(50 * sizeof(char));
        int recv_bytes;
        while ((recv_bytes = recv(args->new_fd, buf, 49, 0)) != 0) {
            buf[recv_bytes] = '\0';

            pthread_mutex_lock(&lock);
            fputs(buf, msgfile);
            pthread_mutex_unlock(&lock); 


            memset(buf, '\0', sizeof(buf));

            if (recv_bytes < 49) {
                size_t nread;
                fseek(msgfile, 0, SEEK_SET);
                while ((nread = fread(buf, 1, 49, msgfile)) > 0) {
                    buf[nread] = '\0';
                    printf("%s\n", buf);
                    int r = send(args->new_fd, buf, nread, MSG_NOSIGNAL);
                }
            }
        }

        fclose(msgfile);
        int count;

        FILE * msgfile2 = fopen("/var/tmp/aesdsocketdata", "r");

        close(args->new_fd);
        fclose(msgfile2);
       pthread_exit(1);

}

int main(int argc, char * argv[]) {
    
    int sockfd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, * servinfo, * p;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    struct sigaction sa;
    {
        /* data */
    };
    

    if (pthread_mutex_init(&lock, NULL) != 0) { 
        printf("\n mutex init has failed\n"); 
        return 1; 
    } 

    LIST_HEAD(listhead, entry) head =
        LIST_HEAD_INITIALIZER(head);

    struct entry *item = malloc(sizeof(struct entry));      /* Insert at the head. */
    LIST_INSERT_HEAD(&head, item, entries);

    LIST_INIT(&head);

    memset( & hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, & hints, & servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p -> ai_next) {
        if ((sockfd = socket(p -> ai_family, p -> ai_socktype,
                p -> ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, & yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        // setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&yes, sizeof(int));

        if (bind(sockfd, p -> ai_addr, p -> ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure
    system("rm /var/tmp/aesdsocketdata");



    if (argv[0] = "-d") {
        if (!fork()) {
            if (p == NULL) {
                fprintf(stderr, "server: failed to bind\n");
                exit(1);
            }

            if (listen(sockfd, BACKLOG) == -1) {
                perror("listen");
                exit(1);
            }


            while (1) {
            struct sockaddr_storage their_addr; // connector's address information

                socklen_t sin_size = sizeof their_addr;

                int new_fd = accept(sockfd, (struct sockaddr * ) & their_addr, & sin_size);
                if (new_fd == -1) {
                    perror("accept");
                    return;
                }
            printf("server: waiting for connections...\n");
            threadparams params;

            params.new_fd = new_fd;
            pthread_t thread_id;
            printf("Before Thread\n");
            
            pthread_create( & thread_id, NULL, myThreadFun, &params);
            struct entry *item = malloc(sizeof(struct entry));
            item->value = thread_id;
            item->completeflag = 0;
            LIST_INSERT_HEAD(&head, item, entries);

            struct entry *item_for;
            LIST_FOREACH(item_for, &head, entries)
            {  
                FILE * msgfile = fopen("/var/tmp/aesdsocketdata", "a+");
                if (msgfile == NULL) {
                    syslog(LOG_ERR, "couldn't open file for writing");
                return -1;
                 }
                char outstr[200];
                time_t t;
                struct tm *tmp;
                t = time(NULL);
           tmp = localtime(&t);
           if (tmp == NULL) {
               perror("localtime");
               exit(EXIT_FAILURE);
           }
            int sec = tmp->tm_sec;
            int prev_sec;
           if (strftime(outstr, sizeof(outstr), "%c", tmp) == 0) {
               fprintf(stderr, "strftime returned 0");
               exit(EXIT_FAILURE);
           }

            if(prev_sec >= sec - 10)
            {
                fputs("timestamp:", msgfile);
                fputs(outstr, msgfile);
                fputs("\n", msgfile);
            } 
            prev_sec = sec;
            fclose(msgfile);

                if(!item_for->completeflag )          
                    pthread_join(thread_id, &item->completeflag );
           
            }

            
            printf("After Thread\n");

            sa.sa_handler = sigchld_handler; // reap all dead processes

            if (sigaction(SIGINT, & sa, NULL) != 0) {
                perror("sigINT");
                exit(0);
            }
            if (sigaction(SIGTERM, & sa, NULL) != 0) {
                perror("sigTem");
                exit(0);
            }

        } // parent doesn't need this
    }
    return 0;
    }
}