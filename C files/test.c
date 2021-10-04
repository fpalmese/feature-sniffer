#include <stdio.h>

#include "array2.h"
/*
void main(){
	Array32 arr;
	initArray32(&arr,3);
	insertArray32(&arr,1);
	printf("size of array: %d\t",arr.size);
	printf("first element of array: %d\n",arr.array[0]);
	insertArray32(&arr,2);
	printf("size of array: %d\t",arr.size);
	printf("second element of array: %d\n",arr.array[0]);
	insertArray32(&arr,1);
	printf("size of array: %d\t",arr.size);
	printf("third element of array: %d\n",arr.array[0]);
	insertArray32(&arr,4);
	printf("size of array: %d\t",arr.size);
	printf("fourth element of array: %d\n",arr.array[0]);
	insertArray32(&arr,55);
	printf("size of array: %d\t",arr.size);
	printf("fifth element of array: %d\n",arr.array[0]);
	freeArray32(&arr);
}*/

char netmask=16;
unsigned long routerIp=3232235778; //192.168.1.2


int checkNetmask(unsigned long ip){
	return (routerIp >> (32-netmask)) == (ip >> (32-netmask));
}

int checkIPBroadcast(unsigned long ip){
	return (ip & ((1<< (32-netmask))-1)) == ( (1<< (32-netmask)) -1);
}



void main(){
	unsigned long toTest = 3232301054;
	printf("ip is: %d.%d.%d.%d\n",toTest>>24, (toTest & 0x00FF0000 )>>16,(toTest & 0x0000FF00) >>8, toTest & 0x000000FF);
	printf("ip is in netmask: %d\n", checkNetmask(toTest));
	printf("ip is broadcast: %d\n", checkIPBroadcast(toTest));





}








