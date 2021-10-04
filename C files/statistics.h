#include <math.h>
#include <stdlib.h>




/*	--------------------------

STATISTICS FUNCTIONS FOR ARRAYS OF INTs

-------------------------------	*/

int cmpint (const void * a, const void * b) {
   return (*(int*)b < *(int*)a );
}

unsigned long long sum_int(unsigned int *array, char size){
	unsigned long long sum =0;
	for(int i=0;i<size;i++)
		sum +=array[i];
	return sum;
}

double mean_int(unsigned int *array, char size){
	unsigned long long sum = sum_int(array,size);
	return (sum/(double)size);
}

double median_int(unsigned int *array, char size) {
	qsort(array, size, sizeof(int), cmpint);
	if(size%2==0)
		return((array[size/2] + array[size/2 - 1]) / 2.0);
	else
		return array[size/2];
}

unsigned int mode_int(unsigned int *array,char size) {
   unsigned int maxValue = 0;
   int maxCount = 0,i, j;

   for (i = 0; i < size; ++i) {
      int count = 0;
      for (j = 0; j < size; ++j) {
         if (array[j] == array[i])
         ++count;
      }
      if (count > maxCount) {
         maxCount = count;
         maxValue = array[i];
      }
   }
   return maxValue;
}

double variance_int(unsigned int *array, char size) {
	double variance = 0.0, mean;
	mean=mean_int(array,size);
	for (int i = 0; i < size; i++)
		variance += pow(array[i] - mean, 2);
	return (variance/(double)size);
}

double stdev_int(unsigned int *array, char size) {
	double variance = variance_int(array,size);
	return sqrt(variance);
}


double kurtosis_int(unsigned int *array, char size){
	double mean,stdev=0.0,kurtosis=0.0;
	mean = mean_int(array,size);
	for (int i = 0; i < size; i++)
		stdev += pow(array[i] - mean, 2);
	stdev = sqrt(stdev/(double)size);
	for (int i = 0; i < size; i++)
		kurtosis += pow((array[i] - mean) / stdev, 4);

	return ((kurtosis/(double)size) -3);
}



/*	--------------------------

STATISTICS FUNCTIONS FOR ARRAYS OF DOUBLEs

-------------------------------	*/
int cmpdbl (const void * a, const void * b) {
   return (*(double*)b < *(double*)a );
}


double sum_double(double *array, char size){
	double sum = 0;
	for(int i=0;i<size;i++)
		sum+=array[i];
	return sum;
}


double mean_double(double *array, char size){
	double sum = sum_double(array,size);
	return (sum/(double)size);
}

double median_double(double *array, char size) {
	qsort(array, size, sizeof(double), cmpdbl);
	if(size%2==0)
		return((array[size/2] + array[size/2 - 1]) / 2.0);
	else
		return array[size/2];
}


double variance_double(double *array, char size) {
	double variance = 0.0, mean;
	mean = mean_double(array,size);
	for (int i = 0; i < size; i++)
		variance += pow(array[i] - mean, 2);
	
	return (variance/(double)size);
}

double stdev_double(double *array, char size) {
	double variance = variance_double(array,size);
	return sqrt(variance);
}


double kurtosis_double(double *array, char size){
	double mean,stdev=0.0,kurtosis=0.0;
	mean = mean_double(array,size);
	for (int i = 0; i < size; i++)
		stdev += pow(array[i] - mean, 2);
	sqrt(stdev/(double)size);
	for (int i = 0; i < size; i++)
		kurtosis += pow((array[i] - mean) / stdev, 4);
	return (kurtosis/(double)size);
}









