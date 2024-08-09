#ifndef FW_H
#define FW_H

#define A_PORT  6
#define B_PORT 7



struct flow_ctx_table_key {
	/*per-application */
	__u16 ip_proto;
	__u16 l4_src;
	__u16 l4_dst;
	__u32 ip_src;
	__u32 ip_dst;

};

struct flow_ctx_table_leaf {
	int out_port;
	int in_port;
//	flow_register_t flow_reg;
};


#endif /* FW_H */
