#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("========================================================================\n");
    printf("%u bytes captured\n", header->caplen);
    printf("Destination MAC Address : %02X-%02X-%02X-%02X-%02X-%02X\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
    printf("Source MAC Address : %02X-%02X-%02X-%02X-%02X-%02X\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    printf("Type : ");
    if(0x0800==(packet[12]<<8|packet[13])){
        printf("IPv4\n");
        int k=(packet[14]&0x0F)*4;
        printf("Source IP : %d.%d.%d.%d \n", packet[6+k],packet[7+k],packet[8+k],packet[9+k]);
        printf("Destination IP : %d.%d.%d.%d \n", packet[10+k],packet[11+k],packet[12+k],packet[13+k]);
        if(0x06==packet[23])
        {
            printf("Layer4 Type : TCP\n");
            printf("Source Port : %d \n", (packet[14+k]<<8)|packet[15+k]);
            printf("Destination Port : %d \n", (packet[16+k]<<8)|packet[17+k]);
            int k1=(packet[26+k]>>4)*4;
            printf("TCP data : %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", packet[14+k+k1],packet[15+k+k1],packet[16+k+k1],packet[17+k+k1],packet[18+k+k1],packet[19+k+k1],packet[20+k+k1],packet[21+k+k1],packet[22+k+k1],packet[23+k+k1]);
        }
        else{
            printf("Layer Type : ETC\n");
        }

    }
    else if(0x0806==(packet[12]<<8|packet[13])){
            printf("ARP\n");
        }
    else{
        printf("etc\n");
    }
    }


  pcap_close(handle);
  return 0;
}
