#include <stdlib.h>
#define array(type)  \
  struct {           \
      type* data;    \
      size_t length; \
      size_t used;   \
  }\

#define array_init(array,size)	\
  do { \
      array.data =malloc(sizeof(*array.data) * size);    \
      array.length = size;  				 \
      array.used = 0;					  \
  } while (0)

#define array_free(array) \
  do {                    \
      free(array.data);   \
      array.data = NULL;  \
      array.length = 0;   \
      array.used = 0;	\
  } while (0)

#define array_push(array, element)                        \
  do {                                                    \
      if(array.used == array.length){			  \
	      array.length *= 2;			  \
	      array.data = realloc(array.data,            \
		                   sizeof(*array.data) *  \
		                     array.length);       \
						          \
      }							  \
      array.data[array.used++] = element;		  \
  } while (0)						  \

												\


#define array_push_unique(array, element,exists)        \
  do {                                                  \
      exists = 0;					\
      for(int i=0;i<array.used;i++){			\
         if(array.data[i] == element) 			\
		exists = 1;				\
     }							\
      if(!exists)					\
	   array_push(array,element); 			\
  } while (0)	


#define array_print(array)					\
	do{							\
								\
		for(int i=0;i<array.used;i++)			\
			printf(", %d",array.data[i]);		\
		printf("\n");					\
	} while(0)						\



//128 = count, 64 = sum, 32 = mean, 16 = median, 8 = mode, 4 = variance, 2 = stdev, 1 = kurtosis; //inverted!! count=1, sum=2 ... kurt=128

#define macro_array_calculate_print_features(outfile,array,check,sum,mean,median,mode,variance,stdev,kurtosis,cmpfunc)	\
do{															\
	sum=0,mean=0,median=0,mode=0,variance=0,stdev=0,kurtosis=0;						\
	int maxCount=0;													\
	if(array.used >0){													\
		for(int i=0;i<array.used;i++){											\
			if( ((check & 64)>0) || ((check & 32)>0) || ((check & 4)>0) || ((check & 2)>0) || ((check & 1)>0))	\
				sum += array.data[i];										\
																\
			if( (check & 8)>0){											\
				int count = 0;											\
				for (int j = 0; j < array.used; ++j) {								\
					if (array.data[j] == array.data[i])							\
						++count;									\
					if (count > maxCount) {									\
						maxCount = count;								\
						mode = array.data[i];								\
					}											\
				}												\
			}													\
		}														\
																\
		if((((check & 32)>0) || ((check & 4)>0) || ((check & 2)>0) || ((check & 1)>0)) && sum>0){			\
			mean = sum / (double)array.used;									\
		}														\
																\
		if((((check & 4)>0) || ((check & 2)>0) || ((check & 1)>0)) && sum>0){						\
			for(int i = 0;i<array.used;i++)										\
				variance += pow(array.data[i] - mean, 2);							\
			variance = variance/(double)array.used;									\
		}														\
																\
		if( ( ( (check & 2)>0) || ((check & 1)>0) ) && sum>0)								\
			stdev = sqrt(variance);											\
																\
		if( ((check & 1) >0) && stdev>0){										\
			for (int i = 0; i < array.used; i++)									\
				kurtosis += pow((array.data[i] - mean) / stdev, 4);						\
			kurtosis = ((kurtosis/(double)array.used) -3);								\
		}														\
																\
																\
		if( ((check & 16) >0) && array.used >0){									\
			qsort(array.data, array.used, sizeof(array.data[0]), cmpfunc);						\
			if(array.used%2==0)											\
				median = ((array.data[array.used/2] + array.data[array.used/2 - 1]) / 2.0);			\
			else													\
				median = array.data[array.used/2];								\
																\
		}														\
																\
	}															\
																\
	if( (check & 128)>0 )													\
		fprintf(outfile,"\t%d",array.used);										\
																\
	if((check & 64)>0){													\
		fprintf(outfile,"\t%0.0lf",(double)sum);									\
																\
	}															\
	if((check & 32)>0){													\
		fprintf(outfile,"\t%0.4lf",(double)mean);									\
	}															\
	if((check & 16)>0){													\
		fprintf(outfile,"\t%0.4lf",(double)median);									\
	}															\
	if((check & 8)>0){													\
		fprintf(outfile,"\t%0.0lf",(double)mode);									\
	}															\
	if( (check & 4)>0){													\
		fprintf(outfile,"\t%0.4lf",(double)variance);									\
	}															\
																\
	if((check & 2)>0){													\
		fprintf(outfile,"\t%0.4lf",(double)stdev);									\
	}															\
	if((check & 1)>0){													\
		fprintf(outfile,"\t%0.4lf",(double)kurtosis);									\
	}														\
																\
																\
																\
																\
}while(0)

//concat array2 and array3, store in array1 (init and allocate array1)
#define macro2_array_concat(array1,array2,array3)									\
  do {														\
	printf("starting concat: len should be %d\n",array2.length+array3.length);				\
	if((array2.used+array3.used)>0){									\
		array_init(array1,array2.used+array3.used);							\
		printf("init ok array of %d, ptr is %p\n",array2.length+array3.length,array1.data);		\
		int min = array2.used < array3.used ? array2.used : array3.used;					\
		int max = array2.used < array3.used ? array3.used : array2.used;					\
		for(int i=0;i<min;i++){						\
			array_push(array1,array2.data[i]);							\
			array_push(array1,array3.data[i]);							\
		}												\
													\
		for(int i=min;i<max;i++){		\
			if(array2.used < array3.used)							\
				array_push(array1,array3.data[i]);					\
			else										\
				array_push(array1,array2.data[i]);					\
		}											\
		printf("array concat ok\n");								\
	}												\
	else												\
		array_init(array1,2);									\
  } while(0)

#define macro_array_concat(array1,array2,array3,type)								\
  do {														\
	if((array2.used+array3.used)>0){									\
		array_init(array1,array2.used+array3.used);							\
		memcpy(array1.data,array2.data,sizeof(*array2.data)*array2.used);				\
		memcpy(array1.data+array2.used,array3.data,sizeof(*array3.data)*array3.used);			\
		array1.used = array2.used+array3.used;								\
	}													\
	else													\
		array_init(array1,1);										\
  } while(0)

int cmpint (const void * a, const void * b) {
   return (*(int*)b < *(int*)a );
}

int cmpdbl (const void * a, const void * b) {
   return (*(double*)b < *(double*)a );
}

int array_concat(void **array1, void *array2, void *array3, int size2, int size3){
	if((size2+size3))
		*array1 = malloc(sizeof(size2+size3));
	if(size2>0)
		memcpy(*array1,array2,size2);
	if(size3>0)
	memcpy(*array1+size2,array3,size3);
}


int array_concat_int(int **array1, int *array2, int *array3, int size2, int size3){
	for(int i=0;i<size2;i++){
		(*array1)[i] = array2[i];
	}
	for(int i=0;i<size3;i++){
		(*array1)[size2+i] = array3[i];
	}
}

char *csvSeparator="\t";

//calculate and print the features for an array of int basing on the check value (1=count, 2=sum,4=mean,8=median,16=mode,32=variance,64=standard_deviation,128=kurtosis)
void array_calculate_print_features_int(FILE *outfile,int *data,int length,int check){
	double sum=0,mean=0,median=0,mode=0,variance=0,stdev=0,kurtosis=0;						
	int maxCount=0;
	if(length>0){													
		for(int i=0;i<length;i++){											
			if((check & (2 + 4 + 64 + 128)) >0)	
				sum += data[i];										
																
			if( (check & 16)>0){											
				int count = 0;											
				for (int j = 0; j < length; ++j) {								
					if (data[j] == data[i])							
						++count;									
					if (count > maxCount) {									
						maxCount = count;								
						mode = data[i];								
					}											
				}												
			}													
		}														
																
		if((((check & 4)>0) || ((check & 32)>0) || ((check & 64)>0) || ((check & 128)>0)) && sum>0){			
			mean = sum / (double)length;									
		}														
																
		if((((check & 32)>0) || ((check & 64)>0) || ((check & 128)>0)) && sum>0){						
			for(int i = 0;i<length;i++)										
				variance += pow(data[i] - mean, 2);							
			variance = variance/(double)length;									
		}														
																
		if( ( ( (check & 64)>0) || ((check & 128)>0) ) && sum>0)								
			stdev = sqrt(variance);											
																
		if( ((check & 128) >0) && stdev>0){										
			for (int i = 0; i < length; i++)									
				kurtosis += pow((data[i] - mean) / stdev, 4);						
			kurtosis = ((kurtosis/(double)length) -3);								
		}														
																
																
		if( ((check & 8) >0) && length >0){
			qsort(data, length, sizeof(int), cmpint);
							
			if(length%2==0)											
				median = ((data[length/2] + data[length/2 - 1]) / 2.0);			
			else													
				median = data[length/2];								
																
		}														
																
	}															
																
	if( (check & 1)>0 )													
		fprintf(outfile,"%s%d",csvSeparator,length);										
																
	if((check & 2)>0){													
		fprintf(outfile,"%s%0.0lf",csvSeparator,(double)sum);									
																
	}															
	if((check & 4)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)mean);									
	}															
	if((check & 8)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)median);									
	}															
	if((check & 16)>0){													
		fprintf(outfile,"%s%0.0lf",csvSeparator,(double)mode);									
	}															
	if( (check & 32)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)variance);									
	}															
																
	if((check & 64)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)stdev);									
	}															
	if((check & 128)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)kurtosis);									
	}														
	fflush(outfile);
}

//calculate and print the features for an array of double basing on the check value  (1=count, 2=sum,4=mean,8=median,32=variance,64=standard_deviation,128=kurtosis)
void array_calculate_print_features_dbl(FILE *outfile,double *data,int length,int check){
	double sum=0,mean=0,median=0,variance=0,stdev=0,kurtosis=0;
	
	if(length>0){													
		for(int i=0;i<length;i++){											
			if((check & (2 + 4 + 64 + 128)) >0)
				sum += data[i];											
		}														
																
		if((((check & 4)>0) || ((check & 32)>0) || ((check & 64)>0) || ((check & 128)>0)) && sum>0){			
			mean = sum / (double)length;									
		}														
																
		if((((check & 32)>0) || ((check & 64)>0) || ((check & 128)>0)) && sum>0){						
			for(int i = 0;i<length;i++)										
				variance += pow(data[i] - mean, 2);							
			variance = variance/(double)length;									
		}														
																
		if( ( ( (check & 64)>0) || ((check & 128)>0) ) && sum>0)								
			stdev = sqrt(variance);											
																
		if( ((check & 128) >0) && stdev>0){										
			for (int i = 0; i < length; i++)									
				kurtosis += pow((data[i] - mean) / stdev, 4);						
			kurtosis = ((kurtosis/(double)length) -3);								
		}														
																
																
		if( ((check & 8) >0) && length >0){
			qsort(data, length, sizeof(double), cmpdbl);			
			if(length%2==0)											
				median = ((data[length/2] + data[length/2 - 1]) / 2.0);			
			else													
				median = data[length/2];								
												
		}

	}													
	if( (check & 1)>0 )													
		fprintf(outfile,"%s%d",csvSeparator,length);										
																
	if((check & 2)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)sum);									
																
	}															
	if((check & 4)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)mean);									
	}															
	if((check & 8)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)median);									
	}
	if((check & 16)>0){													
		fprintf(outfile,"%s--",csvSeparator);									
	}																															
	if( (check & 32)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)variance);									
	}															
																
	if((check & 64)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)stdev);									
	}															
	if((check & 128)>0){													
		fprintf(outfile,"%s%0.4lf",csvSeparator,(double)kurtosis);									
	}
	fflush(outfile);
}
