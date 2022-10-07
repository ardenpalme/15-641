#include "queue.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>


queue_t* queue_init(){
    queue_t* q = malloc(sizeof(queue_t));
    q->front = NULL;
    return q;
}

bool is_empty(queue_t* q){
    return q->front == NULL;
}

elem_t* pop(queue_t* q){
    elem_t* res = q->front;
    elem_t* tmp = q->front->next;
    q->front = tmp;
    return res;
}

bool is_in_queue(queue_t* q, mixnet_address addr){
    elem_t* curr = q->front;

    while(curr != NULL){
        if (curr->path->addr == addr) return true;
        curr = curr->next;
    }

    return false;
}

void add_item(queue_t* q, mixnet_address addr){
    elem_t* new = malloc(sizeof(elem_t));
    new->path = malloc(sizeof(path_t));
    new->next = NULL;
    new->path->addr = addr;
    new->path->next = NULL;

    elem_t* curr = q->front;   
    if (curr == NULL){ // Cold add
        q->front = new;
        return;
    } else {
        while(curr->next != NULL){ //Insert after last list elem
            curr = curr->next;
        }
        curr->next = new;
    }
}

void print_queue(queue_t* q){
    elem_t* curr = q->front;
    printf("[");
    while(curr != NULL){
        print_path(curr->path);
        printf(",");
        curr = curr->next;
    }
    printf("]\n");
}

void print_path(path_t* p){
    path_t* curr = p;
    printf("[");
    while(curr != NULL){
        printf("%u ", curr->addr);
        curr = curr->next;
    }
    printf("]");
}

void add_path(queue_t* q, path_t* path){
    elem_t* new = malloc(sizeof(elem_t));
    new->path = path;
    new->next = NULL;

    elem_t* curr = q->front;   
    if (curr == NULL){ // Cold add
        q->front = new;
        return;
    } else {
        while(curr->next != NULL){ //Insert after last list elem
            curr = curr->next;
        }
        curr->next = new;
    }
}

path_t* get_end_of_path(path_t* path){            
    path_t* tmp = path;    
    while (tmp->next != NULL){
        tmp = tmp->next;
    }
    return tmp;
}

void extend_path(path_t* path, mixnet_address extension){
    path_t* tmp = path;
    while (tmp->next != NULL){
        tmp = tmp->next;
    }
    path_t* new = malloc(sizeof(path_t));
    new->addr = extension;
    new->next = NULL;

    tmp->next = new;
}

path_t* copy_path(path_t* path){
    path_t *tmp;
    path_t *result;
    result = malloc(sizeof(path_t));
    result->addr = path->addr;
    path = path->next;

    tmp = result;
    while (path != NULL){
        tmp->next = malloc(sizeof(path_t));
        tmp->next->addr = path->addr;
        tmp = tmp->next;
        path = path->next;        
    }
    tmp->next = NULL;

    return result;
}

void print_queue(queue_t *route_queue) {
    elem_t* ele = route_queue->front;
    path_t* path;
    while(ele != NULL){
        path = ele->path;
        printf("%u: [ ", path->addr);
        while(path != NULL){
            printf("%u ", path->addr);
            path = path->next;
        }
        
        ele = ele->next;
        printf("]\n");
    }
    printf("\n");
}