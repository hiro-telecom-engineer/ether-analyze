# coding: utf -8
import PySimpleGUI as sg # ライブラリの読み込み
import re
import analyze

# テーマの設定
sg.theme("SystemDefault ")

# ダンプデータ
L_dump_input = [
    [sg.Multiline(default_text="",
    border_width=1,
    size=(75,60),
    autoscroll=True,
    key="-DUMP_INPUT_DATA-")]
]
# 整形データ
L_dump_output = [
    [sg.Multiline(default_text="",
    border_width=1,
    size=(75,30),
    autoscroll=True,
    key="-DUMP_OUTPUT_DATA-")]
]
# 解析開始ボタン
L_start_btn = sg.Button("開始",
                            border_width=4 ,
                            size =(58,1),
                            key="-BTN_START-")
# 宛先MACアドレス
L_ether_mac_addr_des = [
    sg.Text("・Destination MAC address", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(20,1) ,
    key="-ETHER_MAC_DES_ADDR-")
]
# 送信元MACアドレス
L_ether_mac_addr_src =[
    sg.Text("・source MAC address", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(20,1) ,
    key="-ETHER_MAC_SRC_ADDR-")
]
# VLAN
L_ether_tpid = [
    sg.Text("・TPID", size=(19,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-ETHER_VLAN_TPID-")
]
# TCI
L_ether_tci =[
    [
        sg.Text("・PCP", size=(18,1)) ,
        sg.InputText(default_text="" ,
        size=(10,1) ,
        key="-ETHER_VLAN_PCP-")
    ],
    [
        sg.Text("・CFI", size=(18,1)) ,
        sg.InputText(default_text="" ,
        size=(10,1) ,
        key="-ETHER_VLAN_CFI-")
    ],
    [
        sg.Text("・VID", size=(18,1)) ,
        sg.InputText(default_text="" ,
        size=(10,1) ,
        key="-ETHER_VLAN_VID-")
    ],
]
# タイプ
L_ether_type =[
    sg.Text("・Type", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-ETHER_TYPE-")
]
# IPヘッダ
# Version
L_ip_version = [
    sg.Text("・Version", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_VERSION-")
]
# IHL
L_ip_ihl = [
    sg.Text("・IHL", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_IHL-")
]
# TOS
L_ip_tos =[
    [
        sg.Text("・DSCP", size=(19,1)) ,
        sg.InputText(default_text="" ,
        size=(10,1) ,
        key="-IP_TOS_DSCP-")
    ],
    [
        sg.Text("・ECT", size=(19,1)) ,
        sg.InputText(default_text="" ,
        size=(10,1) ,
        key="-IP_TOS_ECT-")
    ],
    [
        sg.Text("・CE", size=(19,1)) ,
        sg.InputText(default_text="" ,
        size=(10,1) ,
        key="-IP_TOS_CE-")
    ],
]
# Total Length
L_ip_length = [
    sg.Text("・Total Length", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_LENGTH-")
]
# Identification
L_ip_id = [
    sg.Text("・Identification", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_ID-")
]
# Flag
L_ip_flag = [
    sg.Text("・Flag", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_FLAG-")
]
# Flagment Offset
L_ip_offset = [
    sg.Text("・Offset", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_OFFSET-")
]
# TTL
L_ip_ttl = [
    sg.Text("・TTL", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_TTL-")
]
# Protocol
L_ip_protcol = [
    sg.Text("・Protocol", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_PROT-")
]
# Header Checkcum
L_ip_chksum = [
    sg.Text("・Header Checkcum", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(10,1) ,
    key="-IP_CHKSUM-")
]
# Source Address
L_ip_src_addr = [
    sg.Text("・Source IP Address", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(12,1) ,
    key="-IP_SRC_ADDR-")
]
# Destination Address
L_ip_dst_addr = [
    sg.Text("・Destination IP Address", size=(20,1)) ,
    sg.InputText(default_text="" ,
    size=(12,1) ,
    key="-IP_DST_ADDR-")
]
#全体レイアウト
L = [
[
    sg.Frame("解析データ",L_dump_input, size=(480, 800)),
    sg.Frame("解析結果",
    [
        [
            L_start_btn
        ],
        [
            # イーサヘッダ解析結果
            sg.Frame("Ether header",
            [
                L_ether_mac_addr_des,
                L_ether_mac_addr_src,
                [
                    sg.Frame("VLAN",
                    [
                        L_ether_tpid,
                        [
                            sg.Frame("TCI",L_ether_tci, size=(440, 110))
                        ]
                    ], size=(460, 160)
                    )
                ],
                L_ether_type
            ], size=(480, 270)
            )
        ],
        [
            # IPヘッダ解析結果
            sg.Frame("IP header",
            [
                L_ip_version,
                L_ip_ihl,
                [
                    sg.Frame("TOS", L_ip_tos, size=(460, 110))
                ],
                L_ip_length,
                L_ip_id,
                L_ip_flag,
                L_ip_offset,
                L_ip_ttl,
                L_ip_protcol,
                L_ip_chksum,
                L_ip_src_addr,
                L_ip_dst_addr
            ], size=(480, 450)
            )
        ]
    ], size=(400, 800)
    )
],
]

# ウィンドウ作成
window = sg.Window ("Pcket analyze tool", L, resizable=True)
values = ""

def main():
    global values
    # イベントループ
    while True:
        # イベントの読み取り（イベント待ち）
        event , values = window.read()
        # 解析開始
        if event == "-BTN_START-":
            input_txt = re.sub('[^0123456789abcdefABCDEF]', '', values["-DUMP_INPUT_DATA-"])
            update_list = analyze.header_chk(input_txt)
            for update_inf in update_list:
                window[update_inf[0]].Update(update_inf[1])
        # 終了条件（ None: クローズボタン）
        elif event == None:
            print(" 終了します． ")
            break

    # 終了処理
    window.close()

if __name__ == '__main__':
    main()