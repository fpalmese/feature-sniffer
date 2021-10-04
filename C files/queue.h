#include <pthread.h>
#include <semaphore.h>


typedef struct node {
    struct Window *value;
    struct node *next;
} node;

typedef struct {
    node *front;
    node *rear;
    pthread_mutex_t mutex;
    sem_t *sem;
    u_int size;
} Queue;


// qcreate() - crea una coda vuota
Queue* qcreate(){
	// crea la coda
	Queue *queue = malloc(sizeof(Queue));
	// inizializza la coda
	queue->front = NULL;
	queue->rear = NULL;
	queue->size = 0;
	pthread_mutex_init(&queue->mutex, NULL);
	queue->sem = malloc(sizeof(sem_t));
	sem_init(queue->sem,0,0);
	return queue;
}

// enqueue() - aggiunge un elemento alla coda
void enqueue(Queue* queue, struct Window *value){
	// crea un nuovo nodo
	node *temp = malloc(sizeof(struct node));
	temp->value = value;
	temp->next  = NULL;
	// blocco l'accesso
	pthread_mutex_lock(&queue->mutex);
	// test se la coda è vuota
	if (queue->front == NULL) {
		// con la coda vuota front e rear coincidono
		queue->front = temp;
		queue->rear = temp;
		
	}
	else {
		// aggiungo un elemento
		node *old_rear = queue->rear;
		old_rear->next = temp;
		queue->rear    = temp;
	}
	//printf("Enqueued succesfully\n");
	// sblocco l'accesso ed esco
	queue->size++;
	pthread_mutex_unlock(&queue->mutex);
	sem_post(queue->sem);
}


// dequeue() - toglie un elemento dalla coda
int dequeue(Queue* queue, struct Window **value){
	// blocco l'accesso
	pthread_mutex_lock(&queue->mutex);
		// test se la coda è vuota
	node *front = queue->front;
	if (front == NULL) {
		// sblocco l'accesso ed esco
		pthread_mutex_unlock(&queue->mutex);
		return 0;
	}
	// leggo il valore ed elimino l'elemento dalla coda
	*value = front->value;
	queue->front = front->next;
	free(front);
	// sblocco l'accesso ed esco
	queue->size--;
	pthread_mutex_unlock(&queue->mutex);
	return 1;
}

#ifdef DEBUG_VAR
void printQueue(Queue *queue){
	printf("\n----------------------\nthis is the queue:\n");
	node *val=queue->front;
	while(val != NULL){
		printStdoutWindow(val->value);
		val = val-> next;
	}
	printf("------------------------\n\n");
}
#endif


