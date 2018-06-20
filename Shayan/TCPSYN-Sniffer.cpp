// Shayan Javid
// Dr. Bartlett
// TCP-SYN sniffer using libpcap


#include <stdio.h>
#include <pcap.h>
#include <iostream>
using namespace std;

static int packetCount = 0;
void packetHandler(u_char*, const struct pcap_pkthdr*, const u_char*);
/*
 callback function to handle packets based on packet_handler type ( http://www.tcpdump.org/pcap.htm )
 */

int main(int argc, char *argv[])
{
    char* dev = NULL;       //device
    bpf_program fcode;      // Berkeley packet filter struct - accessing to the data link layers for packets to be sent or received
    char filter_exp[] = "tcp[tcpflags] & (tcp-ack) == 0 and (tcp-syn) != 0";       // Setting the filter expression to TCP SYN
    char errbuf[PCAP_ERRBUF_SIZE];      // buffer that contains libcap errors
    bpf_u_int32 subnet_mask = 0, ip = 0;
    pcap_t* handle;     //pcap handle
    dev = pcap_lookupdev(errbuf);       //returns a pointer to a string containing the name of the first network device suitable
    if (dev == NULL)
    {
        cout << "No device was found." << errbuf << endl;
        return 1;
    }
    if (pcap_lookupnet(dev, &ip, &subnet_mask, errbuf)==-1) //if's condition: find the ip and the netmask for a device
    {
        cout << "Could not get information of the device (" << dev << ")" << endl;
    }
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // opening the device for a live capture
    
    if (handle == NULL)
    {
        cout << "Could not open the device." << errbuf << endl;
        return 1;
    }
        if (pcap_setdirection (handle, PCAP_D_IN) == -1)    // if's condition: setting the direction of the device to look for receiving packages
    {
        cout << "Direction was not set: " << pcap_geterr(handle) << endl;
    }
    
    if (pcap_compile(handle, &fcode, filter_exp, 0, ip) == -1)  //if's condition: compiling the filter (TCP SYN) before applying it
    {
        cout << "Bad filter" << pcap_geterr(handle) << endl;
        return 1;
    }
    
    if (pcap_setfilter(handle, &fcode) == -1) { //if's condition: setting the filter (TCP SYN)
        cout << "Error. The filter was not set." << pcap_geterr(handle) << endl;
        return 1;
    }
    
    //Pcap_loop
    pcap_loop(handle, 0, packetHandler, NULL);  // processing multiple packets with pcap_loop with our filter
    //Close
    pcap_close(handle);
    return 0;
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    cout << ++packetCount <<" packets were found " << endl;
}
