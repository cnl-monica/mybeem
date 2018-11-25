#ifndef _PACKETIDENT_H_
#define _PACKETIDENT_H_
struct identificator_s* ip_packet_identificator(const unsigned char* packet,const unsigned char length_of_identificator);
void ip_packet_identificator_MD5(uint8_t *m_digest, const unsigned char* packet);
#endif
