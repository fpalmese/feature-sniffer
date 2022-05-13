#include "sniffer.h"
#include "queue.h"


//-----------------------------------------------
//-----------------------------------------------
//-----------------------------------------------

int num_packets = -1;
char *WFileName = "./output";
char *defaultOutputName = "capture";
char *RFileName = NULL;
char *SFileName = NULL;
char *currentFilename;
char *interface = NULL;

//int numWindows=0, numEnqueued=0,numDequeued=0;		DBG



char captureRunning = 1;

pcap_t *handle;                   /* packet capture handle */

Queue *queuedWindows = NULL;	/*windows in queue to be printed out*/
int count = 0;

/*		
 * callback for a packet: add the interested properties to the correct window (append the old window if time slot ended)
 */
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
	double ts = time_to_double(header->ts.tv_sec,header->ts.tv_usec);
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;     /* The ethernet header*/
	const struct sniff_ip *ip;                 /* The IP header */
	const void *transport;             		  /* The transport header (tcp, udp) */
	const char *payload;                       /* Packet payload */
	u_int size_ip;
	u_int size_transport;
	u_int size_payload;
	u_int s_port,d_port;
	char exists=0;
	count++;
	Window *window_src = NULL;
	Window *window_dst = NULL;
	int src,dst;
	int pdfIndex;
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	/* define/compute ip header offset */
	size_ip = IP_HL(ip)*4;

	if(size_ip<20)//Invalid IP header length
		return;
		
	if(ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP)//Invalid protocol
		return;
	
	if(startingTime <0){
		startingTime = ts;
		current_filetime = startingTime;
	}
	//at first check the netmasks from the ip of the devices
	src = checkNetmask(ip->ip_src);
	dst = checkNetmask(ip->ip_dst) & !checkIPBroadcast(ip->ip_dst);

	if(macFromFile){	//labels are from file: consider only those devices.
		if(src){	//if ip src is netmaks take the window if exists (if not exists then dont take the device)
			if((src = getWindowIndex(&(ethernet->ether_shost)))>=0){
				window_src = allWindows.data[src];
				if(window_src->timestamp<=0.0)
					allWindows.data[src]->timestamp = (startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime);
			}
		}
		if(dst){	//do same as src
			if((dst = getWindowIndex(&(ethernet->ether_dhost)))>=0){
				window_dst = allWindows.data[dst];
				if(window_dst->timestamp<=0.0)
					allWindows.data[dst]->timestamp = (startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime);
			}
		}
		//src and dest are not in the label file, ignore packet
		if(window_src==NULL && window_dst==NULL) 
			return;
	}

	else{	//labels are not from file, take any mac in same network
		if(src){	//crea nuovo device per source (se non esiste gia)
			if((src = getWindowIndex(&ethernet->ether_shost))< 0){	//e aggiungi il giusto tempo alla finestra
				src = addDevice(&ethernet->ether_shost);
			}
			window_src = allWindows.data[src];
			if(window_src->timestamp<=0.0){
				allWindows.data[src]->timestamp = (startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime);
			}
		}
		if(dst){	//crea nuovo device per dest (se non esiste gia)
			if((dst = getWindowIndex(&ethernet->ether_dhost)) < 0){	
				dst = addDevice(&ethernet->ether_dhost);
			}
			window_dst = allWindows.data[dst];
			if(window_dst->timestamp<=0.0){ //aggiungi il giusto tempo alla finestra
				allWindows.data[dst]->timestamp = (startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime);
			}
		}
	}
	//save the label to keep it constant in windows
	int oldLabel = 0;
	if(window_src != NULL && (ts - windowTime >= (window_src->timestamp))){	//if window src is old, enqueue to print and set a new window
		/*
		oldLabel = window_src->label;
		enqueue(queuedWindows,window_src);
		//numEnqueued++;	DBG

		window_src = window_init();
		allWindows.data[src] = window_src;

		//maintain old window params (dev,index,label) and set new time
		memcpy(window_src->device, &(ethernet->ether_shost),6);
		window_src->index = src;
		window_src->label = oldLabel;
		window_src->timestamp = (startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime);
		*/

		//reinit the window with empty values (maintain dev,index,label) and set the new time
		allWindows.data[src] = window_reinit(window_src,(startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime));
		enqueue(queuedWindows,window_src);
		window_src = allWindows.data[src];

	}	
	if(window_dst != NULL && (ts - windowTime >= (window_dst->timestamp))){		//if window dst is old, enqueue to print and set a new window
		/*		
		oldLabel = window_dst->label;
		enqueue(queuedWindows,window_dst);

		//numEnqueued++;	DBG
		//allWindows.data[dst] = window_init();	//set a new window and set the timestamp
		//window_dst = allWindows.data[dst];
		

		window_dst = window_init();
		allWindows.data[dst] = window_dst;


		memcpy(window_dst->device, &(ethernet->ether_dhost),6);
		window_dst->index = dst;
		window_dst->label = oldLabel;
		window_dst->timestamp = (startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime);
		*/

		//reinit the window with empty values (maintain dev,index,label) and set the new time
		allWindows.data[dst] = window_reinit(window_dst,(startingTime + ((int)( (ts-startingTime) /windowTime )) * windowTime));  
		enqueue(queuedWindows,window_dst);
		window_dst = allWindows.data[dst];



	}
	/*determine protocol */
	switch(ip->ip_p){
		/*handle TCP packets*/
		case IPPROTO_TCP:
			/* define/compute tcp header offset */
			transport = (struct sniff_tcp*)(packet + SIZE_ETHERNET +size_ip);
			size_transport = TH_OFF( (struct sniff_tcp*)transport )*4;
			if (size_transport < 20) {
				// Invalid TCP header length
				return;
			}
			s_port = ntohs(((struct sniff_tcp*)transport)->th_sport);
			d_port = ntohs(((struct sniff_tcp*)transport)->th_dport);

			//payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_transport);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_transport);
			pdfIndex = ((u_int)(ntohs(ip->ip_len)+ SIZE_ETHERNET))/100;
			if(pdfIndex > 15)
				pdfIndex = 15;

			if(window_src != NULL){
				//packet size = ntohs(ip->ip_len)+ SIZE_ETHERNET
				array_push_unique(window_src->remoteIps,(ip->ip_dst).s_addr,exists);
				array_push_unique(window_src->remoteTCPPorts,(u_int)d_port,exists);
				array_push(window_src->tcpULsizes,(u_int)(ntohs(ip->ip_len)+ SIZE_ETHERNET));
				array_push(window_src->tcpPayloadULsizes,(u_int)size_payload);
				array_push_unique(window_src->tcpPorts,(u_int)s_port,exists);
				array_push(window_src->tcpULtimes,ts);
				window_src->tcpULpdf[pdfIndex]++;
			}
			if(window_dst != NULL){// handle here all the window stuff for dst (TCP)
				array_push_unique(window_dst->remoteIps,(ip->ip_src).s_addr,exists);
				array_push_unique(window_dst->remoteTCPPorts,(u_int)s_port,exists);
				array_push(window_dst->tcpDLsizes,(u_int)(ntohs(ip->ip_len)+ SIZE_ETHERNET));
				array_push(window_dst->tcpPayloadDLsizes,(u_int)size_payload);
				array_push_unique(window_dst->tcpPorts,(u_int)d_port,exists);
				array_push(window_dst->tcpDLtimes,ts);
				window_dst->tcpDLpdf[pdfIndex]++;
				//printf("window: %d size: %u pdfIndex: %d value:%d\n",dst,(u_int)(ntohs(ip->ip_len)),pdfIndex,window_dst->tcpDLpdf[pdfIndex]);
			}
			break;

		/*handle UDP packets*/
		case IPPROTO_UDP:
			transport = (struct sniff_udp*)(packet + SIZE_ETHERNET +size_ip);
			size_transport= ntohs( ( (struct sniff_udp*)transport)->uh_ulen);

			if (size_transport < 8) {
				//Invalid UDP header length
				return;
			}
			s_port = ntohs( ((struct sniff_udp*)transport)->uh_sport);
			d_port = ntohs( ((struct sniff_udp*)transport)->uh_dport);


			//payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+SIZE_UDP);
			size_payload = size_transport - SIZE_UDP;
			pdfIndex = ((u_int)(ntohs(ip->ip_len)+ SIZE_ETHERNET))/100;
			if(pdfIndex > 15)
				pdfIndex = 15;

			if(window_src != NULL){// handle here all the window stuff for src (UDP)
				array_push_unique(window_src->remoteIps,(ip->ip_dst).s_addr,exists);
				array_push_unique(window_src->remoteUDPPorts,(u_int)d_port,exists);
				array_push(window_src->udpULsizes,(u_int)(ntohs(ip->ip_len)+ SIZE_ETHERNET));
				array_push(window_src->udpPayloadULsizes,(u_int)size_payload);
				array_push_unique(window_src->udpPorts,(u_int)s_port,exists);
				array_push(window_src->udpULtimes,ts);
				window_src->udpULpdf[pdfIndex]++;
			}
			if(window_dst != NULL){// handle here all the window stuff for dst (UDP)
				array_push_unique(window_dst->remoteIps,(ip->ip_src).s_addr,exists);
				array_push_unique(window_dst->remoteUDPPorts,(u_int)s_port,exists);
				array_push(window_dst->udpDLsizes,(u_int)(ntohs(ip->ip_len)+ SIZE_ETHERNET));
				array_push(window_dst->udpPayloadDLsizes,(u_int)size_payload);
				array_push_unique(window_dst->udpPorts,(u_int)d_port,exists);
				array_push(window_dst->udpDLtimes,ts);
				window_dst->udpDLpdf[pdfIndex]++;
			}
			break;

		default:
			return;
	}
	//for restricted memory, use this
	if(RFileName!= NULL)
		usleep(1);
	return;
}

//function used to calculate and print all the features from a single window
void printWindowFeatures(Window *window){
	//don't print null windows
	if(window->timestamp<=0.0){
		window_free(window);
		return;
	}
	//HERE CALCULATE ALL FEATURES!
	if(splitByMac){
		currentFile = filePerMac[window->index];
	}
	char mac[17];
	ether_ntoa_r(window->device,mac); //thread-safe ether_ntoa
	fprintf(currentFile,"%.3f%s%s",(window->timestamp - relativeTime * startingTime),csvSeparator,mac);
	int size;
	array(u_int) temp;
	

	//--------------------------------------------------------------//
	//			PACKET SIZE FEATURES			//
	//--------------------------------------------------------------//

	//-------TCP-----------//
	//tcpDLsizes
	array_calculate_print_features_int(currentFile,window->tcpDLsizes.data,window->tcpDLsizes.used,featureSelect[0]);
	//tcpULsizes
	array_calculate_print_features_int(currentFile,window->tcpULsizes.data,window->tcpULsizes.used,featureSelect[1]);

	//tcpSizes
	size = window->tcpDLsizes.used + window->tcpULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpDLsizes.data,sizeof(u_int)*window->tcpDLsizes.used);
		memcpy(temp.data+window->tcpDLsizes.used,window->tcpULsizes.data,sizeof(u_int)*window->tcpULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[2]);
	array_free(temp);
	
	//-------UDP-----------//
	//udpDLsizes
	array_calculate_print_features_int(currentFile,window->udpDLsizes.data,window->udpDLsizes.used,featureSelect[3]);
	//udpULsizes
	array_calculate_print_features_int(currentFile,window->udpULsizes.data,window->udpULsizes.used,featureSelect[4]);

	//udpSizes
	size = window->udpDLsizes.used + window->udpULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->udpDLsizes.data,sizeof(u_int)*window->udpDLsizes.used);
		memcpy(temp.data+window->udpDLsizes.used,window->udpULsizes.data,sizeof(u_int)*window->udpULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[5]);
	array_free(temp);
	
	//---------TOT-----------//
	//totDLsizes
	size = window->tcpDLsizes.used + window->udpDLsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpDLsizes.data,sizeof(u_int)*window->tcpDLsizes.used);
		memcpy(temp.data+window->tcpDLsizes.used,window->udpDLsizes.data,sizeof(u_int)*window->udpDLsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[6]);
	array_free(temp);

	//totULsizes
	size = window->tcpULsizes.used + window->udpULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpULsizes.data,sizeof(u_int)*window->tcpULsizes.used);
		memcpy(temp.data+window->tcpULsizes.used,window->udpULsizes.data,sizeof(u_int)*window->udpULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[7]);
	array_free(temp);
	
	//totSizes
	size = window->tcpDLsizes.used + window->udpDLsizes.used + window->tcpULsizes.used + window->udpULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpDLsizes.data,sizeof(u_int)*window->tcpDLsizes.used);
		memcpy(temp.data+window->tcpDLsizes.used,window->udpDLsizes.data,sizeof(u_int)*window->udpDLsizes.used);
		memcpy(temp.data+window->tcpDLsizes.used+window->udpDLsizes.used,window->tcpULsizes.data,sizeof(u_int)*window->tcpULsizes.used);
		memcpy(temp.data+window->tcpDLsizes.used+window->udpDLsizes.used+window->tcpULsizes.used,window->udpULsizes.data,sizeof(u_int)*window->udpULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[8]);
	array_free(temp);


	//--------------------------------------------------------------//
	//			PAYLOAD SIZE FEATURES			//
	//--------------------------------------------------------------//
	
	//--------TCP----------//
	//tcpDLpld
	array_calculate_print_features_int(currentFile,window->tcpPayloadDLsizes.data,window->tcpPayloadDLsizes.used,featureSelect[9]);
	//tcpULpld
	array_calculate_print_features_int(currentFile,window->tcpPayloadULsizes.data,window->tcpPayloadULsizes.used,featureSelect[10]);
	//tcpPayload
	size = window->tcpPayloadDLsizes.used + window->tcpPayloadULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpPayloadDLsizes.data,sizeof(u_int)*window->tcpPayloadDLsizes.used);
		memcpy(temp.data+window->tcpPayloadDLsizes.used,window->tcpPayloadULsizes.data,sizeof(u_int)*window->tcpPayloadULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[11]);
	array_free(temp);
	
	//--------UDP----------//
	//udpDLpld
	array_calculate_print_features_int(currentFile,window->udpPayloadDLsizes.data,window->udpPayloadDLsizes.used,featureSelect[12]);
	//udpULpld
	array_calculate_print_features_int(currentFile,window->udpPayloadULsizes.data,window->udpPayloadULsizes.used,featureSelect[13]);
	//udpPayload
	size = window->udpPayloadDLsizes.used + window->udpPayloadULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->udpPayloadDLsizes.data,sizeof(u_int)*window->udpPayloadDLsizes.used);
		memcpy(temp.data+window->udpPayloadDLsizes.used,window->udpPayloadULsizes.data,sizeof(u_int)*window->udpPayloadULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[14]);
	array_free(temp);
	
	//--------TOT----------//
	//totDLpld
	size = window->tcpPayloadDLsizes.used + window->udpPayloadDLsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpPayloadDLsizes.data,sizeof(u_int)*window->tcpPayloadDLsizes.used);
		memcpy(temp.data+window->tcpPayloadDLsizes.used,window->udpPayloadDLsizes.data,sizeof(u_int)*window->udpPayloadDLsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[15]);
	array_free(temp);

	//totULpld
	size = window->tcpPayloadULsizes.used + window->udpPayloadULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpPayloadULsizes.data,sizeof(u_int)*window->tcpPayloadULsizes.used);
		memcpy(temp.data+window->tcpPayloadULsizes.used,window->udpPayloadULsizes.data,sizeof(u_int)*window->udpPayloadULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[16]);
	array_free(temp);

	
	//totPld
	size = window->tcpPayloadDLsizes.used + window->udpPayloadDLsizes.used + window->tcpPayloadULsizes.used + window->udpPayloadULsizes.used;
	if(size>0){
		array_init(temp,size);
		memcpy(temp.data,window->tcpPayloadDLsizes.data,sizeof(u_int)*window->tcpPayloadDLsizes.used);
		memcpy(temp.data+window->tcpPayloadDLsizes.used,window->udpPayloadDLsizes.data,sizeof(u_int)*window->udpPayloadDLsizes.used);
		memcpy(temp.data+window->tcpPayloadDLsizes.used+window->udpPayloadDLsizes.used,window->tcpPayloadULsizes.data,sizeof(u_int)*window->tcpPayloadULsizes.used);
		memcpy(temp.data+window->tcpPayloadDLsizes.used+window->udpPayloadDLsizes.used+window->tcpPayloadULsizes.used,window->udpPayloadULsizes.data,sizeof(u_int)*window->udpPayloadULsizes.used);
		temp.used = size;
	}
	else
		array_init(temp,1);
	array_calculate_print_features_int(currentFile,temp.data,temp.used,featureSelect[17]);
	array_free(temp);


	//--------------------------------------------------------------//
	//		   INTERARRIVAL TIME FEATURES			//
	//--------------------------------------------------------------//


	double *inter=NULL;
	array(double) temp_dbl;

	//-------TCP DL---------//
	if(window->tcpDLtimes.used>=2){
		size = window->tcpDLtimes.used-1;
		timesToInter(&inter,window->tcpDLtimes.data,window->tcpDLtimes.used);
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[18]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}
	
	//-------TCP UL---------//
	if(window->tcpULtimes.used>=2){
		size = window->tcpULtimes.used-1;
		timesToInter(&inter,window->tcpULtimes.data,window->tcpULtimes.used);
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[19]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}	
	//-------TCP DL+UL--------//
	size = window->tcpDLtimes.used + window->tcpULtimes.used;
	if(size>=2){
		array_init(temp_dbl,size);
		memcpy(temp_dbl.data,window->tcpDLtimes.data,sizeof(double)*window->tcpDLtimes.used);
		memcpy(temp_dbl.data+window->tcpDLtimes.used,window->tcpULtimes.data,sizeof(double)*window->tcpULtimes.used);
		temp_dbl.used = size;
		qsort(temp_dbl.data,temp_dbl.used, sizeof(double), cmpdbl);		//sort the times in the concat
		timesToInter(&inter,temp_dbl.data,temp_dbl.used);
		array_free(temp_dbl);
		size = size-1; //inter have size -1
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[20]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}

	
	//-------UDP DL---------//
	if(window->udpDLtimes.used>=2){
		size = window->udpDLtimes.used-1;
		timesToInter(&inter,window->udpDLtimes.data,window->udpDLtimes.used);
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[21]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}
	
	//-------UDP UL---------//
	if(window->udpULtimes.used>=2){
		size = window->udpULtimes.used-1;
		timesToInter(&inter,window->udpULtimes.data,window->udpULtimes.used);
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[22]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}	
	//-------UDP DL+UL---------//
	size = window->udpDLtimes.used + window->udpULtimes.used;
	if(size>=2){
		array_init(temp_dbl,size);
		memcpy(temp_dbl.data,window->udpDLtimes.data,sizeof(double)*window->udpDLtimes.used);
		memcpy(temp_dbl.data+window->udpDLtimes.used,window->udpULtimes.data,sizeof(double)*window->udpULtimes.used);
		temp_dbl.used = size;
		qsort(temp_dbl.data,temp_dbl.used, sizeof(double), cmpdbl);		//sort the times in the concat
		timesToInter(&inter,temp_dbl.data,temp_dbl.used);
		array_free(temp_dbl);
		size = size-1; //inter have size -1
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[23]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}


	
	//-------TOT DL---------//
	size = window->tcpDLtimes.used + window->udpDLtimes.used;
	if(size>=2){
		array_init(temp_dbl,size);
		memcpy(temp_dbl.data,window->tcpDLtimes.data,sizeof(double)*window->tcpDLtimes.used);
		memcpy(temp_dbl.data+window->tcpDLtimes.used,window->udpDLtimes.data,sizeof(double)*window->udpDLtimes.used);
		temp_dbl.used = size;
		qsort(temp_dbl.data,temp_dbl.used, sizeof(double), cmpdbl);		//sort the times in the concat
		timesToInter(&inter,temp_dbl.data,temp_dbl.used);
		array_free(temp_dbl);
		size = size-1; //inter have size -1
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[24]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}

	//-------TOT UL---------//
	size = window->tcpULtimes.used + window->udpULtimes.used;
	if(size>=2){
		array_init(temp_dbl,size);
		memcpy(temp_dbl.data,window->tcpULtimes.data,sizeof(double)*window->tcpULtimes.used);
		memcpy(temp_dbl.data+window->tcpULtimes.used,window->udpULtimes.data,sizeof(double)*window->udpULtimes.used);
		temp_dbl.used = size;
		qsort(temp_dbl.data,temp_dbl.used, sizeof(double), cmpdbl);		//sort the times in the concat
		timesToInter(&inter,temp_dbl.data,temp_dbl.used);
		array_free(temp_dbl);
		size = size-1; //inter have size -1
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[25]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}

	//-------TOT DL + UL---------//
	size = window->tcpDLtimes.used + window->udpDLtimes.used + window->tcpULtimes.used + window->udpULtimes.used;
	if(size>=2){
		array_init(temp_dbl,size);
		memcpy(temp_dbl.data,window->tcpDLtimes.data,sizeof(double)*window->tcpDLtimes.used);
		memcpy(temp_dbl.data+window->tcpDLtimes.used,window->udpDLtimes.data,sizeof(double)*window->udpDLtimes.used);
		memcpy(temp_dbl.data+window->tcpDLtimes.used+window->udpDLtimes.used,window->tcpULtimes.data,sizeof(double)*window->tcpULtimes.used);
		memcpy(temp_dbl.data+window->tcpDLtimes.used+window->udpDLtimes.used+window->tcpULtimes.used,window->udpULtimes.data,sizeof(double)*window->udpULtimes.used);
		temp_dbl.used = size;
		qsort(temp_dbl.data,temp_dbl.used, sizeof(double), cmpdbl);		//sort the times in the concat
		timesToInter(&inter,temp_dbl.data,temp_dbl.used);
		array_free(temp_dbl);
		size = size-1; //inter have size -1
	}
	else{
		size = 0;
	}
	array_calculate_print_features_dbl(currentFile,inter,size,featureSelect[26]);
	if(inter!= NULL){
		free(inter);
		inter = NULL;
	}
	
	//-------------------------------------------------------------------//
	//--------------------Packet distribution of sizes FEATURES----------//
	//-------------------------------------------------------------------//
	
	int temp_pdf_vector[16];
	//-------TCP DL---------//
	print_pdf_vector(currentFile,window->tcpDLpdf,16,featureSelect[27]);	

	//-------TCP UL---------//
	print_pdf_vector(currentFile,window->tcpULpdf,16,featureSelect[28]);

	//-------TCP DL+UL---------//
	for(int i=0;i<16;i++){
		temp_pdf_vector[i] = window->tcpDLpdf[i] + window->tcpULpdf[i];
	}
	print_pdf_vector(currentFile,temp_pdf_vector,16,featureSelect[29]);
	

	//-------UDP DL---------//
	print_pdf_vector(currentFile,window->udpDLpdf,16,featureSelect[30]);	

	//-------UDP UL---------//
	print_pdf_vector(currentFile,window->udpULpdf,16,featureSelect[31]);

	//-------UDP DL+UL---------//
	for(int i=0;i<16;i++){
		temp_pdf_vector[i] = window->udpDLpdf[i] + window->udpULpdf[i];
	}
	print_pdf_vector(currentFile,temp_pdf_vector,16,featureSelect[32]);


	//-------TOT=TCP+UDP  DL--------//
	for(int i=0;i<16;i++){
		temp_pdf_vector[i] = window->tcpDLpdf[i] + window->udpDLpdf[i];
	}
	print_pdf_vector(currentFile,temp_pdf_vector,16,featureSelect[33]);
	
	//-------TOT=TCP+UDP  UL--------//
	for(int i=0;i<16;i++){
		temp_pdf_vector[i] = window->tcpULpdf[i] + window->udpULpdf[i];
	}
	print_pdf_vector(currentFile,temp_pdf_vector,16,featureSelect[34]);

	//-------TOT=TCP+UDP DL+UL--------//
	for(int i=0;i<16;i++){
		temp_pdf_vector[i] =  window->tcpDLpdf[i] + window->tcpULpdf[i] + window->udpDLpdf[i] + window->udpULpdf[i];
	}
	print_pdf_vector(currentFile,temp_pdf_vector,16,featureSelect[35]);
	
	

	//last features (tcp ports, udp ports, remoteTcpPorts, remoteUdpPorts, remoteIpPorts)
	
	if((featureSelect[36] & 1)>0){													
		fprintf(currentFile,"%s%d",csvSeparator,window->tcpPorts.used);									
	}															
	if((featureSelect[36] & 2)>0){													
		fprintf(currentFile,"%s%d",csvSeparator,window->udpPorts.used);									
	}
	if((featureSelect[36] & 4)>0){													
		fprintf(currentFile,"%s%d",csvSeparator,window->remoteTCPPorts.used);									
	}																											
	if((featureSelect[36] & 8)>0){													
		fprintf(currentFile,"%s%d",csvSeparator,window->remoteUDPPorts.used);
	}
	if((featureSelect[36] & 16)>0){
		fprintf(currentFile,"%s%d",csvSeparator,window->remoteIps.used);
	}

	
	//add label at the end of the row (last column) if needed
	if(addLabel){
		fprintf(currentFile,"%s%d",csvSeparator,window->label);

	}
	fprintf(currentFile,"\n");
	fflush(currentFile);

	//printf("printed window with index, label:%d,  %d\n",window->index,window->label);
	//fflush(stdout);
	window_free(window);
}

//print a pdf vector based on the check bits (print i-th int if i-th bit is 1)
void print_pdf_vector(FILE *file, int *vector, int size, int check){
	int index = 1;
	for(int i=0;i<size;i++){
		if (check & index)
			fprintf(file,"%s%d",csvSeparator,vector[i]);
		index*=2;
	}
	fflush(file);
}

//this function scans the queue and prints(and removes) all the "old file" windows (lock the queue mutex first and unlock after)
void checkOldWindowsWORKING(Queue *qWindows){
	pthread_mutex_lock(&qWindows->mutex);
	node *previous = NULL;	//previous node 	
	node *current = qWindows->front; //current node
	node *next = NULL;
	Window *currentWindow;
	//Window **windowsToPrint = malloc(sizeof(Window*) * qWindows->size);	//store the windows to print in a list, so you can unlock the queue for next enqueue
	
	while(current != NULL){
		currentWindow = current->value;
		//check if current window is old, if it is, print it and then change the queue
		if(currentWindow->timestamp + windowTime - rotate <= current_filetime){
			printWindowFeatures(currentWindow);
			//if removing the front, update it with the next node
			if(previous==NULL)
				qWindows->front = current->next;
			else //if there is a previous, update the previous->next with the current-> next
				previous->next = current->next;
				
			//if removing the rear, update it with the previous node
			if(current->next == NULL)
				qWindows->rear = previous;
			//you can finally free memory of current removed node
			next = current->next;
			free(current);
			//current = current->next; // update the current node with the next in the list
			qWindows->size--;
		}
		else{	//if you did not remove the current node, then you can update the previous with the current (otherwise the previous is the same)	
			previous = current; // update the current node with the next in the list
			next = current->next;
		}
		//current = previous->next;
		current = next;
	}
	pthread_mutex_unlock(&qWindows->mutex);
}
//this function scans the queue and prints(and removes) all the "old file" windows (lock the queue mutex first and unlock after)
void checkOldWindows(Queue *qWindows){
	pthread_mutex_lock(&qWindows->mutex);
	node *previous = NULL;	//previous node 	
	node *current = qWindows->front; //current node
	node *next = NULL;
	Window *currentWindow;
	array(Window*) windowsToPrint;
	array_init(windowsToPrint,qWindows->size);
	while(current != NULL){
		currentWindow = current->value;
		//check if current window is old, if it is, print it and then change the queue
		if(currentWindow->timestamp + windowTime - rotate <= current_filetime){
			//windowsToPrint[numWin++] = currentWindow;
			array_push(windowsToPrint,currentWindow);
			//if removing the front, update it with the next node
			if(previous==NULL)
				qWindows->front = current->next;
			else //if there is a previous, update the previous->next with the current-> next
				previous->next = current->next;
				
			//if removing the rear, update it with the previous node
			if(current->next == NULL)
				qWindows->rear = previous;
			//you can finally free memory of current removed node
			next = current->next;
			free(current);
			qWindows->size--;
		}
		else{	//if you did not remove the current node, then you can update the previous with the current (otherwise the previous is the same)	
			previous = current; 
			next = current->next;
		}
		current = next; // update the current node with the next in the list
	}
	pthread_mutex_unlock(&qWindows->mutex);
	//unlock the queue then print the windows

	for(int i=0;i<windowsToPrint.used;i++){
		printWindowFeatures(windowsToPrint.data[i]);
	}
	array_free(windowsToPrint);

}



//this function is the life of the separated thread: wait for the queue and print the windows in there
void printQueuedWindows(void* arguments){
	Window *window;
	while(1){
		//printQueue(queuedWindows);
		if(!dequeue(queuedWindows,&window)){
			if(!captureRunning){
				if(queuedWindows->size >0)
					continue;
				break;
			}
			sem_wait(queuedWindows->sem);
			continue;
		}
		//numDequeued++;		DBG


		//if there is the rotation option, check that the window should go in the current file, otherwise change the file
		if(rotate && window->timestamp + windowTime - rotate > current_filetime){
			//enqueue all the window with an old file
			Window *win;
			for(int i=0;i<allWindows.used;i++){
				win = allWindows.data[i];
				if(win->timestamp + windowTime - rotate <= current_filetime && win->timestamp>0.0){
					enqueue(queuedWindows,win);
					allWindows.data[i] = window_reinit(win, 0.0); //reinit the window with empty timestamp (because you didnt get packets for the windows yet)
				}
			}
			//print all the old windows present in the queue, in the current file
			checkOldWindows(queuedWindows);
			
			//then you can update the file
			current_filetime = startingTime + ((int)((window->timestamp + windowTime - startingTime)/rotate) * rotate);
			rotate_count = (rotate_count+1)%rotate_max;
			
			//update all files if splitting by mac
			if(splitByMac){
				//char *newFilename = (char *)malloc(PATH_MAX + 1);
				for(int i=0;i<allWindows.used;i++){
					sprintf(currentFilename,"%s/%s/%s%d.csv",WFileName,ether_ntoa(allWindows.data[i]->device),defaultOutputName,rotate_count);
					fclose(filePerMac[i]); //close all old files
					filePerMac[i] = fopen(currentFilename,"w"); //and open the new ones
					if(printHeaders)
						printFeatureHeaders(filePerMac[i]);
				}
			}
			// otherwise update the single file used
			else{
				//currentFilename = (char *)malloc(PATH_MAX + 1);
				sprintf(currentFilename,"%s/%s%d.csv",WFileName,defaultOutputName,rotate_count);
				fclose(currentFile); //close old file
				currentFile = fopen(currentFilename,"w"); // and open the new one
				if(printHeaders)
					printFeatureHeaders(currentFile);

			}
		}	
		printWindowFeatures(window);
	}
}

//convert the array of times into array of inter-arrival times (n times-> n-1 interarrival)
void timesToInter(double **inter,double *array,int size){
	double first;
	*inter = (double*)malloc( (size - 1)*sizeof(double));
	first = array[0];
	for(int i=1;i<size;i++){
		(*inter)[i-1] = (double)(array[i]-first);
		first = array[i];
	}
}

//print headers in file
void printFeatureHeaders(FILE * featureFile){
	fprintf(featureFile,"%s\n",headerString);
	fflush(featureFile);
}


void init_pdf_vector(int **vector,int size,int init_value){
	*vector = malloc(size * sizeof(int));
	for(int i=0;i<size;i++)
		(*vector)[i] = init_value;
}

//init a new window (all parameters empty or 0)
Window* window_init(){
	//numWindows++;	DBG
	Window *window;
	window = malloc(sizeof(Window));
	window->index = 0;
	window->label = 0;
	window->timestamp = 0.0;
	window->device = malloc(sizeof(struct ether_addr));	//alloc mem for device addr (6 bytes)

	array_init(window->tcpDLsizes,25);
	array_init(window->tcpULsizes,25);
	array_init(window->udpDLsizes,25);
	array_init(window->udpULsizes,25);

	array_init(window->tcpPayloadDLsizes,25);
	array_init(window->tcpPayloadULsizes,25);
	array_init(window->udpPayloadDLsizes,25);
	array_init(window->udpPayloadULsizes,25);

	array_init(window->tcpDLtimes,25);
	array_init(window->tcpULtimes,25);
	array_init(window->udpDLtimes,25);
	array_init(window->udpULtimes,25);

	array_init(window->tcpPorts,10);
	array_init(window->udpPorts,10);
	array_init(window->remoteTCPPorts,10);
	array_init(window->remoteUDPPorts,10);
	array_init(window->remoteIps,25);

	memset(window->tcpDLpdf,0,16*sizeof(int));
	memset(window->tcpULpdf,0,16*sizeof(int));
	memset(window->udpDLpdf,0,16*sizeof(int));	
	memset(window->udpULpdf,0,16*sizeof(int));
	return window;
}

//init the window for the next tim
Window* window_reinit(Window* window,double time){
	Window *new_window = window_init(); //init a new window
	new_window->index = window->index; //copy index
	new_window->label = window->label; //copy label
	new_window->timestamp = time; //set new time
	memcpy(new_window->device, window->device,6); //copy mac
	return new_window; //return the new window

}


//add a new device and return its index. (please call only if device does not exist already)
int addDevice(struct ether_addr *dev){
	//printf("adding new device: %s\n",ether_ntoa(dev));	//DBG
	Window *win;
	win = window_init();
	memcpy(win->device, dev,6);
	array_push(allWindows,win);

	FILE * file = NULL;
	/* Append the new file in the array for the mac (print headers if needed)*/

	if(splitByMac){
		char *mkdirpath = malloc(PATH_MAX + 1);
		sprintf(mkdirpath,"%s/%s",WFileName,ether_ntoa(dev));
		mkdir(mkdirpath);
		free(mkdirpath);
		
		if(rotate)
			sprintf(currentFilename,"%s/%s/%s%d.csv",WFileName,ether_ntoa(dev),defaultOutputName,rotate_count);
		else
			sprintf(currentFilename,"%s/%s/%s.csv",WFileName,ether_ntoa(dev),defaultOutputName);
		file = fopen(currentFilename,"w");
		if(printHeaders)
			printFeatureHeaders(file);
		if(usedFiles == lenFiles){
			lenFiles *=2;
			filePerMac = realloc(filePerMac,lenFiles * sizeof(FILE*));
		}
	 	filePerMac[usedFiles++] = file;

	}
	win->label = allWindows.used;
	win->index = allWindows.used-1;
	return win->index;
}


//load the mac (as string) from the file: convert to mac address and add a new window with addDevice function
void loadMacFromSettings(char *mac){
	if(mac==NULL)
		return;
	struct ether_addr dev;
	char mac_string[17];
	strncpy(mac_string,mac,17);
	dev = macStringToEtheraddr(mac_string);
	addDevice(&dev);
}

//load the config settings from the file specified in -s option (use libconfig library)
void loadConfigSettings(){
	config_t cfg;
 	config_setting_t *setting;
 	const char *str;
	int select;
	config_init(&cfg);
	//read config file
	fflush(stdout);
	if(! config_read_file(&cfg, SFileName)){
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
		    config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(EXIT_FAILURE);
	}
	
	//load ip and netmask of router (read the string and parse to long int for ip, read int for mask)
	config_lookup_int(&cfg,"mask",&netmask);
	config_lookup_string(&cfg,"ip",&str);
	struct in_addr *rIp = malloc(sizeof(struct in_addr));
	if(!inet_aton(str,rIp)){
		printf("invalid ip address in config\n");
		exit(0);
	}
	routerIp = ntohl(rIp->s_addr);
	//free(rIp);

	//load addLabel
	config_lookup_int(&cfg,"addLabel",&select);
	addLabel = (char)(select & 0xFF);

	//load window time
	config_lookup_float(&cfg, "winTime", &windowTime);
	
	//load printHeaders
	config_lookup_int(&cfg,"printHeaders",&select);
	printHeaders = (char)(select & 0xFF);

	//load rotation if set
	config_lookup_int(&cfg,"rotateTime",&rotate);
	if(rotate > 0){
		config_lookup_int(&cfg,"rotateMaxFiles",&rotate_max);
		rotate_count=0;
	}
	else
		rotate=0;

	//load ReadFilename
	if(config_lookup_string(&cfg,"readFile",&str)==CONFIG_TRUE){
		RFileName = malloc(strlen(str)+1);
		sprintf(RFileName,"%s",str);
	}
	
	//load Interface (if readFile is not loaded)
	else if(config_lookup_string(&cfg,"interface",&str)==CONFIG_TRUE){
		interface = malloc(strlen(str)+1);
		sprintf(interface,"%s",str);
	}

	//load splitMacFile
	config_lookup_int(&cfg,"splitByMac",&select);
	splitByMac = (char)(select & 0xFF);

	//load captureFilter
	if(config_lookup_string(&cfg,"captureFilter",&str)==CONFIG_TRUE){
		filterString = malloc(strlen(str)+1);
		sprintf(filterString,"%s",str);
	}
	
	//load csvSeparator
	if(config_lookup_int(&cfg,"csvSeparator",&select)==CONFIG_TRUE){
		switch(select){
			case 1:
				csvSeparator="\t";
				break;
			case 2:
				csvSeparator=",";
				break;
			case 3:
				csvSeparator=" ";
				break;
			case 4:
				csvSeparator="-";
				break;
			case 5:
				csvSeparator=";";
				break;
			case 6:
				csvSeparator="|";
				break;
			case 7:
				csvSeparator="||";
				break;
			default:
				csvSeparator = "\t";
				break;
		}
	}
	else
		csvSeparator = "\t";
	
	//init header string
	if(printHeaders){
		headerString = malloc(headerStringAllocated);
		sprintf(headerString,"TS%sDev",csvSeparator);
	}
	//load features by list and setup the printHeader string (if printHeader is true);
	setting = config_lookup(&cfg, "featuresList");
	int numFeatures = config_setting_length(setting);
	//char *name;	(using the same char* str as up)
	//printf("allocating: %d\n",numFeatures);	//DBG
	featureSelect = (int*) malloc(numFeatures*sizeof(int));
	
	char *tempString;
	int tempSize;
	//stat name used for the header construction
	char statNames[8][4] = {"Cnt","Sum","Mu","Mdn","Mod","Var","StD","Krt"};
	int selectIndex;

	//features built on tcp,udp etc
	for(int i =0;i<numFeatures-10;i++){
		config_setting_t *ftr= config_setting_get_elem(setting, i);
		config_setting_lookup_int(ftr,"select",&select);
		featureSelect[i] = (int)(select & 0xFFFF);
		config_setting_lookup_string(ftr,"name",&str);
		if(printHeaders){	//the header string is changed by making a tempstring, copying the header, adding the new header, and copying back to main header
					//a simple sprintf(headerString,"%s\tNewHeader",headerString) would make it easier but not supported in openwrt
			for(int j=0,selectIndex=1;j<8;j++){
				if( (featureSelect[i] & selectIndex)>0){
					tempSize = strlen(headerString)+strlen(str)+4+strlen(csvSeparator);
					checkHeaderSize(tempSize);
					tempString = malloc(tempSize);
					sprintf(tempString,"%s%s%s%s",headerString,csvSeparator,statNames[j],str);
					strncpy(headerString,tempString,tempSize);
					free(tempString);
				}
				selectIndex*=2;
			}
		}
	}


	//9 features for PDF things (n. of packets with payload in [0,100] in [100,200] etc..)
	for(int i=numFeatures-10;i<numFeatures-1;i++){
		config_setting_t *ftr= config_setting_get_elem(setting, i);
		config_setting_lookup_int(ftr,"select",&select);
		config_setting_lookup_string(ftr,"name",&str);
		featureSelect[i] = (int)(select & 0xFFFF);
		if(printHeaders){
			for(int j=0,selectIndex=1;j<16;j++){
				if( (featureSelect[i] & selectIndex)>0){
					tempSize = strlen(headerString)+strlen(str)+12+strlen(csvSeparator);
					checkHeaderSize(tempSize);
					tempString = malloc(tempSize);
					sprintf(tempString,"%s%s%s[%d-%d]",headerString,csvSeparator,str,j*100,(j+1)*100);
					strncpy(headerString,tempString,tempSize);
					free(tempString);
					//sprintf(headerString,"%s\tCnt%s",headerString,str);
				}
				selectIndex*=2;
			}
		}
	}


	//names for the ip-ports feature header
	char ipPortsNames[5][15]={"TcpPorts","UdpPorts","RemoteTcpPorts","RemoteUdpPorts","RemoteIPs"};

	//last features for ports,remote-ports and remote ips
	config_setting_t *ftr= config_setting_get_elem(setting, numFeatures-1);
	config_setting_lookup_int(ftr,"select",&select);
	featureSelect[numFeatures-1] = (int)(select & 0xFFFF);
	
	if(printHeaders){
		for(int j=0,selectIndex=1;j<5;j++){
			if( (featureSelect[numFeatures-1] & selectIndex)>0){
				tempSize = strlen(headerString)+15+strlen(csvSeparator);
				checkHeaderSize(tempSize);
				tempString = malloc(tempSize);
				sprintf(tempString,"%s%s%s",headerString,csvSeparator,ipPortsNames[j]);
				strncpy(headerString,tempString,tempSize);
				free(tempString);
			}
			selectIndex*=2;
		}
		if(addLabel){
			tempSize = strlen(headerString)+6+strlen(csvSeparator);
			checkHeaderSize(tempSize);
			tempString = malloc(tempSize);
			sprintf(tempString,"%s%sLabel",headerString,csvSeparator);
			strncpy(headerString,tempString,tempSize);
			free(tempString);
			//sprintf(headerString,"%s\tLabel",headerString);
		}
		
	}
	
	//load relativeTime
	config_lookup_int(&cfg,"relativeTime",&select);
	relativeTime = (char)(select & 0xFF);

	//load devices from settings
	char *mac;
	int numDevices = 0;
	setting = config_lookup(&cfg, "devicesMacs");
	if(setting!= NULL)
		numDevices = config_setting_length(setting);
	//init array for output files
	if(splitByMac){ 	
		//array_init(filePerMac,(numDevices>0)? numDevices : 10);
		lenFiles = (numDevices>0)? numDevices : 10;
		filePerMac = (FILE*)malloc(sizeof(FILE*)*lenFiles);
	}
	
	if(numDevices>0){
		macFromFile = 1;
		for(int i=0;i<numDevices;i++){
			mac = config_setting_get_string_elem(setting,i);
			loadMacFromSettings(mac);
		}
		mac = NULL;
		if(addLabel){ //load labels from configs if exist
			int numLabels;
			if((setting = config_lookup(&cfg, "labels")) != NULL){
				numLabels = config_setting_length(setting);
				numLabels = (numLabels < numDevices) ? numLabels:numDevices;	//set numLabels as the minimum
				for(int i=0;i<numLabels;i++)
					allWindows.data[i]->label = config_setting_get_int_elem(setting,i);
			}
			else
				numLabels = 0;
			//fix missing labels giving the same as the index (useful when have less labels than devices, or no labels specified
			for(int i=numLabels;i<numDevices;i++)
				allWindows.data[i]->label = (allWindows.data[i]->index)+1;
		}
	}
	config_destroy(&cfg);
}

//convert string to mac address (struc ether_addr)
struct ether_addr macStringToEtheraddr(char* macString){
	struct ether_addr eth;
	//eth->ether_addr_octet
	if (sscanf(macString, "%X:%X:%X:%X:%X:%X",
		&eth.ether_addr_octet[0],
		&eth.ether_addr_octet[1],
		&eth.ether_addr_octet[2],
		&eth.ether_addr_octet[3],
		&eth.ether_addr_octet[4],
		&eth.ether_addr_octet[5]) < 6)
		fprintf(stderr, "could not parse %s\n", macString);
	return eth;
}

//stop the capture when got a SIGINT
void intHandler(int dummy){
	if(captureRunning){
		//printf("Interrupted\n");
		pcap_breakloop(handle);
	}
	else
		exit(0);
}

void checkHeaderSize(int newSize){
	//if header string is full, realloc memory
	if(newSize >= headerStringAllocated){
		headerStringAllocated*=2;
		headerString = realloc(headerString,headerStringAllocated);
	}
}
int main(int argc, char **argv){
	char errbuf[PCAP_ERRBUF_SIZE];    /* error buffer */
	pthread_t thread_id;
	array_init(allWindows,10);
	queuedWindows = qcreate();
	signal(SIGINT, intHandler);	//redefine SIGINT
	bpf_u_int32 mask;                 /* subnet mask */
	bpf_u_int32 net;                  /* ip */
	struct bpf_program fp;            /*  compiled filter program (expression) */
	/* parse command line arguments */
	if (parse_arguments(argc,argv) !=0)
		return 1;
	
	currentFilename = (char *)malloc(PATH_MAX + 1);

	/* parse settings */
	if(SFileName != NULL)
		loadConfigSettings();

	if(!splitByMac){	//init the output file
		//strcpy(currentFilename,WFileName);
		if(rotate)
			sprintf(currentFilename,"%s/%s%d.csv",WFileName,defaultOutputName,rotate_count);
		else
			sprintf(currentFilename,"%s/%s.csv",WFileName,defaultOutputName);
		
		currentFile = fopen(currentFilename,"w");
		
		if(printHeaders){
			printFeatureHeaders(currentFile);
		}
		//delete the headerString
		if(!rotate)	
			free(headerString);
	}
	printf("windowTime: %f relativeTime: %d addLabel: %d, printHeaders: %d, splitByMac: %d, macFromFile: %d, readFile: %d, filterString = %s\n",windowTime,relativeTime, addLabel, printHeaders, splitByMac, macFromFile, RFileName!=NULL, filterString);	//DBG

	//create thread that waits windows ready to print
	pthread_create(&thread_id, NULL, printQueuedWindows, NULL);

	//DBG: print all mac specified in list in config file:
	//for (int i=0;i<allWindows.used;i++)
	//	printf("Device -%d-  %s\n",i+1,ether_ntoa(allWindows.data[i]->device));

	if(RFileName != NULL) //start offline capture if readFile is specified
		handle = pcap_open_offline(RFileName, errbuf);

	else{	//start online capture
		/* check for interface. take an'interface if not specified in command */
		if(interface==NULL){
			interface = pcap_lookupdev(errbuf);
			if (interface == NULL){
				fprintf(stderr,"Counld't find default device: %s\n",errbuf);
				exit(EXIT_FAILURE);
			}
		}

		/* get network number and mask associated with capture device */
		if(pcap_lookupnet(interface,&net,&mask,errbuf) == -1){
			fprintf(stderr,"Couldn't get netmask for device %s: %s\n",interface,errbuf);
			net = 0;
			mask =0;
		}

		/* DBG: print capture info */
		//printf("Interface: %s\n",interface);			//DBG
		//printf("Number of packets: %d\n", num_packets);	//DBG
		//printf("Output file: %s\n",currentFilename);		//DBG
		//printf("Filter expression: %s\n", filterString);	//DBG

		handle = pcap_open_live(interface,SNAP_LEN,1,1000,errbuf);


		if(handle == NULL){
			fprintf(stderr,"Couldn't open device %s: %s\n",interface,errbuf);
			exit(EXIT_FAILURE);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if(pcap_datalink(handle) != DLT_EN10MB){
			fprintf(stderr,"%s is not an Ethernet\n",interface);
			exit(EXIT_FAILURE);
		}
	}

	/* NOT IMPLEMENTED YET: READ FROM CONFIG THE FILTER EXPRESSION AND COMPILE.*/
	
	if(pcap_compile(handle,&fp,filterString,0,net) == -1){
		fprintf(stderr,"Couldn't parse filter %s: %s\n",filterString,pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	/* apply the compiled filter */
	
	if(pcap_setfilter(handle,&fp) == -1){
		fprintf(stderr,"Couldn't install filter %s: %s\n",filterString,pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	

	/* now we can set our callback function: got_packet */
	//printf("right before pcap loop\n");		DBG
	pcap_loop(handle,num_packets,got_packet,NULL);
	/* cleanup */
	//pcap_freecode(&fp);
	pcap_close(handle);

	//printf("\nCapture complete.\n");	//DBG
	//printf("Before: numWindows: %d, numEnqueued: %d ,numDequeued: %d\n",numWindows,numEnqueued,numDequeued);	//DBG
	
	finalExport();
	captureRunning = 0;

	//wake up thread for synchronization reasons
	sem_post(queuedWindows->sem);
	usleep(100);
	sem_post(queuedWindows->sem);
	
	pthread_join(thread_id, NULL);
	closeFiles();

	//printf("After join: numWindows: %d, numEnqueued: %d ,numDequeued: %d\n",numWindows,numEnqueued,numDequeued);		//DBG
	//printf("Total packet parsed: %d\n",count);	//DBG
	
	return 0;
}

//get the index of the device specified in the address (mac)
int getWindowIndex(struct ether_addr *mac){
	for(int i=0; i<allWindows.used;i++){
		if(memcmp(allWindows.data[i]->device,mac, sizeof(struct ether_addr))==0){
			return i;
		}
	}
	//printCurrentWindows();	//DBG
	return -1;
}

//check if ip is in the same subnet of the router
//Tested and working! (beware, the ntohl is used here to invert the bytes)
int checkNetmask(struct in_addr ip){
	//return (ip.s_addr & (-1 <<(32-netmask)) ) == (routerIp & (-1 << (32-netmask)));
	return (routerIp >> (32-netmask)) == ( ntohl(ip.s_addr) >> (32-netmask));
}

//check if the ip is the broadcast address of the subnet(to avoid adding a device for broadcast address
int checkIPBroadcast(struct in_addr ip){
	return (ntohl(ip.s_addr) & ((1<< (32-netmask))-1)) == ( (1<< (32-netmask)) -1);
}

//export last windows not yet exported (when program has been stopped with SIGINT)
void finalExport(){
	Window *finwin;
	for(int i=0;i<allWindows.used;i++){
		finwin = allWindows.data[i];
		//numEnqueued++;		DBG
		if(finwin->timestamp > 0.0)
			enqueue(queuedWindows,finwin);
	}
	array_free(allWindows); //clear the array of all windows
}

//function to parse command line arguments
int parse_arguments(int argc, char **argv){
	int c;
	while ((c = getopt (argc, argv, "c:i:w:G:s:r:")) != -1){
		switch (c){
			//option for max num. of packets to capture
			case 'c':
				num_packets = atoi(optarg);
				break;
			case 'i':
				interface = optarg;
				break;
			case 'w':
				WFileName = optarg;
				break;
			case 's':
				SFileName = optarg;
				break;
			case 'r':
				RFileName = optarg;
				break;
			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c' or it requires an argument.\n", optopt);
				else
					fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
				return 1;
			default:
				abort ();
		}
	}
	return 0;
}

//convert the timestamp (seconds, microseconds) into a double
double time_to_double(long long sec,long long usec) {
	double new_time = (((double) usec )/1000000) + (double)sec;
	return(new_time);
}

//free the window memory
void window_free(Window *window){
	//printf("starting free window\n");
	window->timestamp = 0.0;
	window->index = 0;
	window->label = 0;
	free(window->device);

	array_free(window->tcpDLsizes);
	array_free(window->tcpULsizes);
	array_free(window->udpDLsizes);
	array_free(window->udpULsizes);

	array_free(window->tcpPayloadDLsizes);
	array_free(window->tcpPayloadULsizes);
	array_free(window->udpPayloadDLsizes);
	array_free(window->udpPayloadULsizes);

	array_free(window->tcpDLtimes);
	array_free(window->tcpULtimes);
	array_free(window->udpDLtimes);
	array_free(window->udpULtimes);

	array_free(window->tcpPorts);
	array_free(window->udpPorts);
	array_free(window->remoteTCPPorts);
	array_free(window->remoteUDPPorts);
	array_free(window->remoteIps);

	memset(window->tcpDLpdf,0,16*sizeof(int));
	memset(window->tcpULpdf,0,16*sizeof(int));
	memset(window->udpDLpdf,0,16*sizeof(int));	
	memset(window->udpULpdf,0,16*sizeof(int));

	free(window);
	//printf("end free window\n");
}

void closeFiles(){
	if(splitByMac){
		for(int i=0;i<usedFiles;i++){
			fclose(filePerMac[i]);
		}
	}

	else
		fclose(currentFile);
}







