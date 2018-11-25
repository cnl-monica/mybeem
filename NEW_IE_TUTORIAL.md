# Implementing a support for a new information element
------------------------------------------

During the implementation of a new information element in MyBeem we need to edit the following files. The example below demonstrates the implementation of the *flowLabelIPv6* information element.

### 1. ipfix_infelems.h
This header file is destined for generating an adjusted version of MyBeem. The adjustment is executed using the *beem_adjuster.sh* script. The resulting MyBeem will support the export of only those information elements that are provided (defined) in this header file. The declaration of the new information element must have the following form:
```
#define IPFIX_NAMEOFELEMENT (the ID of the element)
```
In the case of the *flowLabelIPv6* information element the macro will have the following form:
```
#define IPFIX_FLOWLABELIPV6 31
```

### 2. beem_adjuster.sh
Executing this script we can create an adjusted (modified) version of MyBeem. This script only edits the contents of the header file of the previous version of MyBeem and compiles the code. This script must be extended with the following:
```bash
for ((i=0; i<${#c[*]}; i++))
do
case "${c[$i]}" in
...
31) echo "#define IPFIX_FLOWLABELIPV6 ${c[$i]}" >> $filename
im=1
;;
...
*) echo "INVALID ELEMENT \"${c[$i]}\""
;;
esac
done
```

### 3. capture.c
In this file, it is necessary to edit the *processPacket()* function in the following way: First we need to distinguish whether we implement IPv4 or IPv6 packet header support and, based on this, we then edit the corresponding branch. In these branches, we fill the *packet_info* structure into which the fields from the packet header are saved (following the IPFIX specification).

```
void processPacket(struct packet_capturing_thread *t, const u_char *packet)
{
        ...
        
        else if (ntohs(header_ethernet->ether_type) == ETHERTYPE_IPV6)
        {
                ...
                packet_info->ip6_fl = header_ip6->ip6_flow;
                ...
        };
        ...
};
```

### 4. cache.h
In this header file, we need to extend the declaration of the flow in the flow cache with the fields representing the values of the new information element.
```
struct cache_item
{
        ...
        #ifdef IPFIX_FLOWLABELIPV6
        uint32_t		ip6_fl;
        #endif 
        ...
};
```

### 5. cache.c
Within this file, the changes need to be performed in the *add_packet_to_flow()* function. In this file, all the fields are updated triggered by the capture of the packet belonging to a flow. We extend the *item* structure which represents the flow.

```
void add_packet_to_flow(struct cache_item *item, struct _packet_info_t *packet)
{
        ...
        switch(item->flow_state)
        {
                case 0:
                ...
                #ifdef IPFIX_FLOWLABELIPV6                        
                item->ip6_fl = packet->ip6_fl;
                #endif
                ...
        };
        ...
};
```
The #ifdef and #endif directives are destined for those code blocks that are going to ommitted when in a newer version of MyBeem this new information element won't be implemented (supported).

### 6. export.c
In this source file, in the *exportFlow()* function, we extend the "case" branch of the constructor switch for the new information element. The definition of the new information element is located in the *ipfix_def.h* file. It is also necessary to check whether this information element is correctly declared in the *ipfix_fields.h* file.

```
int exportFlow (struct cache_item *flow)
{
        ...            
        for(i=0; i < tmpl[0].field_count;i++)
        {
                ...   
                #ifdef IPFIX_FLOWLABELIPV6                       
                case IPFIX_FT_FLOWLABELIPV6:
                memcpy(buf+offset, &flow->ip6_fl, ie.length);
                break;
                #endif
                ...
        }
        ...
};
```

### 7. config.xml

At last, it is necessary to add the implemented information element into the configuration file. Otherwise this element, although implemented, won't be exported to the collector.
```xml
<configuration>
<templates>
<template id="256">
...
<field>31</field>	<!-- flowLabelIPv6 -->
...
</template>
</templates>
</configuration>
```
