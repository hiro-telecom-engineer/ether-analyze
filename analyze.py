import pandas as pd

# イーサヘッダテーブル
ether_header_tbl = \
[   #"KEY"                  ,"OFFSET_BYTE","OFFSET_BIT" ,"SIZE_BYTE" ,"SIZE_BIT","SIZE","TYPE"
    ["-ETHER_MAC_DES_ADDR-" ,0            ,0            ,6           ,0         ,12        ,"x"  ],
    ["-ETHER_MAC_SRC_ADDR-" ,6            ,0            ,6           ,0         ,12        ,"x"  ],
    ["-ETHER_VLAN_TPID-"    ,12           ,0            ,2           ,0         ,4         ,"x"  ],
    ["-ETHER_VLAN_PCP-"     ,14           ,0            ,0           ,3         ,3         ,"b"  ],
    ["-ETHER_VLAN_CFI-"     ,14           ,3            ,0           ,1         ,1         ,"b"  ],
    ["-ETHER_VLAN_VID-"     ,14           ,1            ,1           ,4         ,3         ,"d"  ],
    ["-ETHER_TYPE-"         ,16           ,0            ,2           ,0         ,4         ,"x"  ],
]

ether_header_df = pd.DataFrame((ether_header_tbl), columns=["KEY","OFFSET_BYTE","OFFSET_BIT" ,"SIZE_BYTE" ,"SIZE_BIT","SIZE","TYPE"])

# IPヘッダテーブル
ip_header_tbl = \
[   #"KEY"                  ,"OFFSET_BYTE","OFFSET_BIT" ,"SIZE_BYTE" ,"SIZE_BIT","SIZE","TYPE"
    ["-IP_VERSION-"         ,0            ,0            ,0           ,4         ,1         ,"d"  ],
    ["-IP_IHL-"             ,0            ,4            ,0           ,4         ,1         ,"d"  ],
    ["-IP_TOS_DSCP-"        ,1            ,0            ,0           ,6         ,2         ,"d"  ],
    ["-IP_TOS_ECT-"         ,1            ,6            ,0           ,1         ,1         ,"b"  ],
    ["-IP_TOS_CE-"          ,1            ,7            ,0           ,1         ,1         ,"b"  ],
    ["-IP_LENGTH-"          ,2            ,0            ,2           ,0         ,4         ,"d"  ],
    ["-IP_ID-"              ,4            ,0            ,2           ,0         ,4         ,"x"  ],
    ["-IP_FLAG-"            ,6            ,0            ,0           ,3         ,3         ,"b"  ],
    ["-IP_OFFSET-"          ,6            ,3            ,1           ,5         ,4         ,"d"  ],
    ["-IP_TTL-"             ,8            ,0            ,1           ,0         ,3         ,"d"  ],
    ["-IP_PROT-"            ,9            ,0            ,1           ,0         ,3         ,"d"  ],
    ["-IP_CHKSUM-"          ,10           ,0            ,2           ,0         ,4         ,"x"  ],
    ["-IP_SRC_ADDR-"        ,12           ,0            ,4           ,0         ,8         ,"x"  ],
    ["-IP_DST_ADDR-"        ,16           ,0            ,4           ,0         ,8         ,"x"  ],
]
ip_header_df = pd.DataFrame((ip_header_tbl), columns=["KEY","OFFSET_BYTE","OFFSET_BIT" ,"SIZE_BYTE" ,"SIZE_BIT","SIZE","TYPE"])

# ヘッダ解析
def header_chk(msg):
    rtn_list = []
    # イーサヘッダ解析
    packet , rtn_list = ether_header_chk(msg)
    # IPヘッダ解析
    rtn_list = ip_header_chk(packet,rtn_list)
    return rtn_list

# イーサヘッダ解析
def ether_header_chk(msg):
    rtn_list = []
    ip_msg = ""
    int_data = int("0x"+msg,16)
    total_bit_size = int(len(msg)/2*8)
    # イーサヘッダテーブル検索
    for index, row in ether_header_df.iterrows():
        # オフセットだけシフト
        offset_bit = row["OFFSET_BYTE"]*8 + row["OFFSET_BIT"] + row["SIZE_BYTE"]*8 + row["SIZE_BIT"]
        shift_data = int_data >> (total_bit_size - offset_bit)
        # サイズ分マスク
        mask_bit = 2**(row["SIZE_BYTE"]*8 + row["SIZE_BIT"]) - 1
        mask_data = shift_data & mask_bit
        # 任意の型へ変換
        if "d" == row["TYPE"]:
            data = int(mask_data)
        else:
            data = format(mask_data, "#0"+ str(row["SIZE"]+2) + row["TYPE"])
        if "-ETHER_VLAN_TPID-" == row["KEY"] and "0x0800" == data :
            update_inf = ["-ETHER_TYPE-",data]
            rtn_list.append(update_inf)
            print(update_inf)
            ip_msg = msg[14*2:]
            break
        elif "-ETHER_TYPE-" == row["KEY"] and "0x0800" == data :
            update_inf = ["-ETHER_TYPE-",data]
            rtn_list.append(update_inf)
            print(update_inf)
            ip_msg = msg[18*2:]
            break
        else:
            update_inf = [row["KEY"],data]
            rtn_list.append(update_inf)
            print(update_inf)
    return ip_msg,rtn_list

# ipヘッダ解析
def ip_header_chk(packet,get_list):
    rtn_list = get_list
    int_data = int("0x"+packet,16)
    total_bit_size = int(len(packet)/2*8)
    for index, row in ip_header_df.iterrows():
        # オフセットだけシフト
        offset_bit = row["OFFSET_BYTE"]*8 + row["OFFSET_BIT"] + row["SIZE_BYTE"]*8 + row["SIZE_BIT"]
        shift_data = int_data >> (total_bit_size - offset_bit)
        # サイズ分マスク
        mask_bit = 2**(row["SIZE_BYTE"]*8 + row["SIZE_BIT"]) - 1
        mask_data = shift_data & mask_bit
        # 任意の型へ変換
        if "d" == row["TYPE"]:
            data = int(mask_data)
        else:
            data = format(mask_data, "#0"+ str(row["SIZE"]+2) + row["TYPE"])
        update_inf = [row["KEY"],data]
        rtn_list.append(update_inf)
        print(update_inf)
    return rtn_list