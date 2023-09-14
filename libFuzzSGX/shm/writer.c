#include <iostream> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stdio.h> 
using namespace std; 
  
int main() 
{ 
    // ftok to generate unique key 
    key_t key = ftok("shmfile",65); 
  
    // shmget returns an identifier in shmid 
    int shmid = shmget(key,1024,0666|IPC_CREAT);
    perror("shmget"); 
  
    // shmat to attach to shared memory 
    char *str = (char*) shmat(shmid,(void*)0,0); 
    perror("shmat");
  
    cout<<"Write Data : "; 
    cin  >> (str); 
  
    printf("Data written in memory: %s\n",str);

   while(1); 
      
    //detach from shared memory  
    shmdt(str); 
  
    return 0; 
} 
