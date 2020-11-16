#include <connection.h>
#include <commands.h>
#include <actions.h>
#include <credentials.h>
#include <database.h>
#include <authentication.h>
#include <pthread.h>


void *connection_loop(void *arg) {

}

void *device_loop(void *arg) {

}

void init_device() {
    pthread_t conn_thread, device_thread;

    

    pthread_create(&conn_thread, NULL, connection_loop, NULL);
    pthread_create(&device_thread, NULL, device_loop, NULL);

}