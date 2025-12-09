// Copyright 1986-2020 Xilinx, Inc. All Rights Reserved.
// --------------------------------------------------------------------------------
// Tool Version: Vivado v.2020.2 (win64) Build 3064766 Wed Nov 18 09:12:45 MST 2020
// Date        : Tue Dec  2 13:48:41 2025
// Host        : MSI running 64-bit major release  (build 9200)
// Command     : write_verilog -force -mode funcsim
//               c:/ECE/4300/ECE4300_FALL2025/Group-B/VexRiscv_Test/VexRiscv_Test.gen/sources_1/ip/blk_mem_gen_1/blk_mem_gen_1_sim_netlist.v
// Design      : blk_mem_gen_1
// Purpose     : This verilog netlist is a functional simulation representation of the design and should not be modified
//               or synthesized. This netlist cannot be used for SDF annotated simulation.
// Device      : xc7a100tcsg324-1
// --------------------------------------------------------------------------------
`timescale 1 ps / 1 ps

(* CHECK_LICENSE_TYPE = "blk_mem_gen_1,blk_mem_gen_v8_4_4,{}" *) (* downgradeipidentifiedwarnings = "yes" *) (* x_core_info = "blk_mem_gen_v8_4_4,Vivado 2020.2" *) 
(* NotValidForBitStream *)
module blk_mem_gen_1
   (clka,
    ena,
    wea,
    addra,
    dina,
    douta);
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA CLK" *) (* x_interface_parameter = "XIL_INTERFACENAME BRAM_PORTA, MEM_SIZE 8192, MEM_WIDTH 32, MEM_ECC NONE, MASTER_TYPE OTHER, READ_LATENCY 1" *) input clka;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA EN" *) input ena;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA WE" *) input [0:0]wea;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA ADDR" *) input [3:0]addra;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA DIN" *) input [31:0]dina;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA DOUT" *) output [31:0]douta;

  wire [3:0]addra;
  wire clka;
  wire [31:0]dina;
  wire [31:0]douta;
  wire ena;
  wire [0:0]wea;
  wire NLW_U0_dbiterr_UNCONNECTED;
  wire NLW_U0_rsta_busy_UNCONNECTED;
  wire NLW_U0_rstb_busy_UNCONNECTED;
  wire NLW_U0_s_axi_arready_UNCONNECTED;
  wire NLW_U0_s_axi_awready_UNCONNECTED;
  wire NLW_U0_s_axi_bvalid_UNCONNECTED;
  wire NLW_U0_s_axi_dbiterr_UNCONNECTED;
  wire NLW_U0_s_axi_rlast_UNCONNECTED;
  wire NLW_U0_s_axi_rvalid_UNCONNECTED;
  wire NLW_U0_s_axi_sbiterr_UNCONNECTED;
  wire NLW_U0_s_axi_wready_UNCONNECTED;
  wire NLW_U0_sbiterr_UNCONNECTED;
  wire [31:0]NLW_U0_doutb_UNCONNECTED;
  wire [3:0]NLW_U0_rdaddrecc_UNCONNECTED;
  wire [3:0]NLW_U0_s_axi_bid_UNCONNECTED;
  wire [1:0]NLW_U0_s_axi_bresp_UNCONNECTED;
  wire [3:0]NLW_U0_s_axi_rdaddrecc_UNCONNECTED;
  wire [31:0]NLW_U0_s_axi_rdata_UNCONNECTED;
  wire [3:0]NLW_U0_s_axi_rid_UNCONNECTED;
  wire [1:0]NLW_U0_s_axi_rresp_UNCONNECTED;

  (* C_ADDRA_WIDTH = "4" *) 
  (* C_ADDRB_WIDTH = "4" *) 
  (* C_ALGORITHM = "1" *) 
  (* C_AXI_ID_WIDTH = "4" *) 
  (* C_AXI_SLAVE_TYPE = "0" *) 
  (* C_AXI_TYPE = "1" *) 
  (* C_BYTE_SIZE = "9" *) 
  (* C_COMMON_CLK = "0" *) 
  (* C_COUNT_18K_BRAM = "1" *) 
  (* C_COUNT_36K_BRAM = "0" *) 
  (* C_CTRL_ECC_ALGO = "NONE" *) 
  (* C_DEFAULT_DATA = "0" *) 
  (* C_DISABLE_WARN_BHV_COLL = "0" *) 
  (* C_DISABLE_WARN_BHV_RANGE = "0" *) 
  (* C_ELABORATION_DIR = "./" *) 
  (* C_ENABLE_32BIT_ADDRESS = "0" *) 
  (* C_EN_DEEPSLEEP_PIN = "0" *) 
  (* C_EN_ECC_PIPE = "0" *) 
  (* C_EN_RDADDRA_CHG = "0" *) 
  (* C_EN_RDADDRB_CHG = "0" *) 
  (* C_EN_SAFETY_CKT = "0" *) 
  (* C_EN_SHUTDOWN_PIN = "0" *) 
  (* C_EN_SLEEP_PIN = "0" *) 
  (* C_EST_POWER_SUMMARY = "Estimated Power for IP     :     3.53845 mW" *) 
  (* C_FAMILY = "artix7" *) 
  (* C_HAS_AXI_ID = "0" *) 
  (* C_HAS_ENA = "1" *) 
  (* C_HAS_ENB = "0" *) 
  (* C_HAS_INJECTERR = "0" *) 
  (* C_HAS_MEM_OUTPUT_REGS_A = "1" *) 
  (* C_HAS_MEM_OUTPUT_REGS_B = "0" *) 
  (* C_HAS_MUX_OUTPUT_REGS_A = "0" *) 
  (* C_HAS_MUX_OUTPUT_REGS_B = "0" *) 
  (* C_HAS_REGCEA = "0" *) 
  (* C_HAS_REGCEB = "0" *) 
  (* C_HAS_RSTA = "0" *) 
  (* C_HAS_RSTB = "0" *) 
  (* C_HAS_SOFTECC_INPUT_REGS_A = "0" *) 
  (* C_HAS_SOFTECC_OUTPUT_REGS_B = "0" *) 
  (* C_INITA_VAL = "0" *) 
  (* C_INITB_VAL = "0" *) 
  (* C_INIT_FILE = "blk_mem_gen_1.mem" *) 
  (* C_INIT_FILE_NAME = "blk_mem_gen_1.mif" *) 
  (* C_INTERFACE_TYPE = "0" *) 
  (* C_LOAD_INIT_FILE = "1" *) 
  (* C_MEM_TYPE = "0" *) 
  (* C_MUX_PIPELINE_STAGES = "0" *) 
  (* C_PRIM_TYPE = "1" *) 
  (* C_READ_DEPTH_A = "16" *) 
  (* C_READ_DEPTH_B = "16" *) 
  (* C_READ_LATENCY_A = "1" *) 
  (* C_READ_LATENCY_B = "1" *) 
  (* C_READ_WIDTH_A = "32" *) 
  (* C_READ_WIDTH_B = "32" *) 
  (* C_RSTRAM_A = "0" *) 
  (* C_RSTRAM_B = "0" *) 
  (* C_RST_PRIORITY_A = "CE" *) 
  (* C_RST_PRIORITY_B = "CE" *) 
  (* C_SIM_COLLISION_CHECK = "ALL" *) 
  (* C_USE_BRAM_BLOCK = "0" *) 
  (* C_USE_BYTE_WEA = "0" *) 
  (* C_USE_BYTE_WEB = "0" *) 
  (* C_USE_DEFAULT_DATA = "0" *) 
  (* C_USE_ECC = "0" *) 
  (* C_USE_SOFTECC = "0" *) 
  (* C_USE_URAM = "0" *) 
  (* C_WEA_WIDTH = "1" *) 
  (* C_WEB_WIDTH = "1" *) 
  (* C_WRITE_DEPTH_A = "16" *) 
  (* C_WRITE_DEPTH_B = "16" *) 
  (* C_WRITE_MODE_A = "WRITE_FIRST" *) 
  (* C_WRITE_MODE_B = "WRITE_FIRST" *) 
  (* C_WRITE_WIDTH_A = "32" *) 
  (* C_WRITE_WIDTH_B = "32" *) 
  (* C_XDEVICEFAMILY = "artix7" *) 
  (* downgradeipidentifiedwarnings = "yes" *) 
  (* is_du_within_envelope = "true" *) 
  blk_mem_gen_1_blk_mem_gen_v8_4_4 U0
       (.addra(addra),
        .addrb({1'b0,1'b0,1'b0,1'b0}),
        .clka(clka),
        .clkb(1'b0),
        .dbiterr(NLW_U0_dbiterr_UNCONNECTED),
        .deepsleep(1'b0),
        .dina(dina),
        .dinb({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .douta(douta),
        .doutb(NLW_U0_doutb_UNCONNECTED[31:0]),
        .eccpipece(1'b0),
        .ena(ena),
        .enb(1'b0),
        .injectdbiterr(1'b0),
        .injectsbiterr(1'b0),
        .rdaddrecc(NLW_U0_rdaddrecc_UNCONNECTED[3:0]),
        .regcea(1'b0),
        .regceb(1'b0),
        .rsta(1'b0),
        .rsta_busy(NLW_U0_rsta_busy_UNCONNECTED),
        .rstb(1'b0),
        .rstb_busy(NLW_U0_rstb_busy_UNCONNECTED),
        .s_aclk(1'b0),
        .s_aresetn(1'b0),
        .s_axi_araddr({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_arburst({1'b0,1'b0}),
        .s_axi_arid({1'b0,1'b0,1'b0,1'b0}),
        .s_axi_arlen({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_arready(NLW_U0_s_axi_arready_UNCONNECTED),
        .s_axi_arsize({1'b0,1'b0,1'b0}),
        .s_axi_arvalid(1'b0),
        .s_axi_awaddr({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_awburst({1'b0,1'b0}),
        .s_axi_awid({1'b0,1'b0,1'b0,1'b0}),
        .s_axi_awlen({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_awready(NLW_U0_s_axi_awready_UNCONNECTED),
        .s_axi_awsize({1'b0,1'b0,1'b0}),
        .s_axi_awvalid(1'b0),
        .s_axi_bid(NLW_U0_s_axi_bid_UNCONNECTED[3:0]),
        .s_axi_bready(1'b0),
        .s_axi_bresp(NLW_U0_s_axi_bresp_UNCONNECTED[1:0]),
        .s_axi_bvalid(NLW_U0_s_axi_bvalid_UNCONNECTED),
        .s_axi_dbiterr(NLW_U0_s_axi_dbiterr_UNCONNECTED),
        .s_axi_injectdbiterr(1'b0),
        .s_axi_injectsbiterr(1'b0),
        .s_axi_rdaddrecc(NLW_U0_s_axi_rdaddrecc_UNCONNECTED[3:0]),
        .s_axi_rdata(NLW_U0_s_axi_rdata_UNCONNECTED[31:0]),
        .s_axi_rid(NLW_U0_s_axi_rid_UNCONNECTED[3:0]),
        .s_axi_rlast(NLW_U0_s_axi_rlast_UNCONNECTED),
        .s_axi_rready(1'b0),
        .s_axi_rresp(NLW_U0_s_axi_rresp_UNCONNECTED[1:0]),
        .s_axi_rvalid(NLW_U0_s_axi_rvalid_UNCONNECTED),
        .s_axi_sbiterr(NLW_U0_s_axi_sbiterr_UNCONNECTED),
        .s_axi_wdata({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_wlast(1'b0),
        .s_axi_wready(NLW_U0_s_axi_wready_UNCONNECTED),
        .s_axi_wstrb(1'b0),
        .s_axi_wvalid(1'b0),
        .sbiterr(NLW_U0_sbiterr_UNCONNECTED),
        .shutdown(1'b0),
        .sleep(1'b0),
        .wea(wea),
        .web(1'b0));
endmodule
`pragma protect begin_protected
`pragma protect version = 1
`pragma protect encrypt_agent = "XILINX"
`pragma protect encrypt_agent_info = "Xilinx Encryption Tool 2020.2"
`pragma protect key_keyowner="Cadence Design Systems.", key_keyname="cds_rsa_key", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=64)
`pragma protect key_block
QGLtnqZzRetDH6gCWT4Js6wuLlZfrNx/VJp3sfR2NF+cxypO5AxN0oDKLJJtmdrtE/ueNDg+Qf7Z
TqBNRojORA==

`pragma protect key_keyowner="Synopsys", key_keyname="SNPS-VCS-RSA-2", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=128)
`pragma protect key_block
B6Ger3hRvfjHkaJ+W8639Kl3TzC9TogLuklOXEiMNdc4Im+DjEUzxb3DKlzu0VW3zxZqjJ3+wsW/
LnRmPCESi5Y9eRJaLFXg79EMfoj4X+nTdHAP6yCfltBADKegZ12gpnB/8ey5yn2KA74LUtPC7jna
iyjqSfsWLGnz6UdXzwk=

`pragma protect key_keyowner="Aldec", key_keyname="ALDEC15_001", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
BX+DxgMPRyZbYojCUR9Sk8Lq+3ZigBz4yMFHQkmurfdfDzyTPJCE827eGiPyTenK1QPVhEtf9g06
0BFXq/0COPuU1BWJwdkz1c4dE6/exDwhvEh+hPx3vRY6z8fDEf6aGVIXrHDvrmddehe7yMSIpo+k
aXHR06EEdfHCFY4TggYwhcJVXjkE+ApsVuyfmEfPmYjo8hCWyQyBsUWIOY03q1+MvUjjsmTwgs9g
fh5MY9ToaLfoJxPKdCpsqrBX4LJ+VDGFlAqIcqHTE2jCmPiToZAFXB7fzf1wDjFCBlJyFVDBGi0i
m+CouLSb7X1mvVhdDZgNrZDJMV688Bu3o54vew==

`pragma protect key_keyowner="ATRENTA", key_keyname="ATR-SG-2015-RSA-3", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
DaIU/Ddc8USbZ2mURzujJDWDH1JbHl5tFVOOQ2aVaUPIA71yyE38OXVLEtF8rNmujYH30nEeQ+FV
LVJ16aaHw+iiuaqorTM3K5KLohVlN+WlcEtSXHuPNHjw8ddqtzpaX7pH1zqZH+YmfCL5oaNLqDH4
rkBnUl0/Gm/hzSwKjYhXGQFYQ+gGP99OjXakzrAqZzp/Iq4gt+Z5902/JV9thd/isHQImJ0QyK8M
EKM579iPAfXGes2mbiNYHcvDmSPYmW1zlhOE++N1EKeea7j/msnKeyhlC+hGE4Xfn4TVvqgQexCT
rp/wS/MosY6WH1aKFQlFH2hEppA7KXUaQlvG+w==

`pragma protect key_keyowner="Mentor Graphics Corporation", key_keyname="MGC-VELOCE-RSA", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=128)
`pragma protect key_block
XmWoAt4X8hrCJ5yTyug4ajJW5UhfkLNibzjihWzZ4Cr9hQSvWZoTc8rjGsLPbz6Le+/9iI5KxecS
eR0wiAO+G2IkwhZgVBeZdKoFnlnTVAyLjk9wMAFXNyJZM6b1NDbfXlPcUsC6JePvPlwwdWknkSsC
r3KvgkWAS+O3xvRmaNw=

`pragma protect key_keyowner="Mentor Graphics Corporation", key_keyname="MGC-VERIF-SIM-RSA-2", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
Hw3Y+rShKrXiUViyNU1/O2qv6TgheLHBnFMj1i9MUGrHYqh9pLfLYUgWR7S2vj4jv4S+Ks0BpP4p
dKEqVAFmTCfQNEUHaVcFPkOHgig6L4mhLY6HUUKJoRgiQepgLi/W3V+ZZPQSQFkB3CU4MsJzhXvR
yLcpDriZy8cnAHD87Zi5DrNGBzj3kigJeM0du6lCQbxtF5aEdoaNP+YTnIFtcqYhoYnswQlYt0sV
HKgFA8VzqzL5WYnpH7+1IKmFkJBHkyqHCa9wPK0qCKnxkuDj70YzPVqQ+cocdKU+/gNdpCOdZlci
F2HTxrgfrXndJru3TiDqu4UavqAe0MNuFp3t0w==

`pragma protect key_keyowner="Real Intent", key_keyname="RI-RSA-KEY-1", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
XPVggoWL6aXz+MpODTOZhEUQDa0vfEnUDaYeEHXm2vGyqKJujN2c/FFAFBeBYdJATLsIsQ+BqoPc
pBbcFYXDBfOtFIW2dH6Y1OoD65KyJ/hAq8coa21kFgq4hFat5vzZ2iIfkCpTUr4vDZO7Xne8cZO9
WsHffoTCt5rS59wWm2b8I5R8Eh2TUbQg3RCyrcnD66cvcEnlXe1CNMQ4/loVJpA4IBinBf820Wjc
vw2fZbGI0jXC+ACSHOviH63Xwmn+aRV5Ppkup7IYoon/ieKapRQeASu3TTY37xSBXiInSdtMTzJ6
+4GfO4eSHVriCk/sWbuTBzfRzoSShrnHjzz5LA==

`pragma protect key_keyowner="Xilinx", key_keyname="xilinxt_2020_08", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
L78XuiswVcgO2gtebzL7SA9BC/jJGAM0v6S9pzmyqL+QYzRneiYeGyDmsW33jEVVSTuNjTXkBLY7
yTOKQruatwe4V0OLi6174saSAmPgerSV1GyLP7KhmusLV/N61avC9TPam+tekhKeE0tds4EnJ3et
4JdLh+SE4Z4pcuqCjB5MFneIYKKWDx7siU6oesAQtoSJOesfMchX63MhOjOHFP/ch+1gHv3T45hg
IGF7V7TrdREVE4f9631tlVJ1o2Dypsmo/76Itz5WCGlTMjAnWXN8IXxKN+PZ3dyt1wjrZm2P/td+
xiGszFnSLrRvw/HferwtSmRx8q0fiHZ88roGTw==

`pragma protect key_keyowner="Metrics Technologies Inc.", key_keyname="DSim", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
kDX5kq2QEe25429T6vQqBCFvV1McKTJRYfK99ymVNK2GGvGLXSzgwJHwB2fj9rM0wme3zYYY0vQR
x+9F4L7KLlOVY6qY3LB59uDzyXBI3mMZaS905HXHJkdZHWtQWpfHhl27LqL+8FSluaD6F+KFfYOV
CwIOVuCIp/XjxFXpNBik7YiPt4kHOlDA97IXNLnYUn/g1csGqeNWce4UTne50ggWvLYGbTFGmTjT
N67TpUiGRVRCSv8Tax72GWFIMFZk3Tlp68ZUSQEybZMWX1U9XdMdtxfvNGhf8mi5jQJ2SupSzKu4
T/+53IN9T8aLePAiGBKKG1ZBj4y1ZyYA7XYvjw==

`pragma protect data_method = "AES128-CBC"
`pragma protect encoding = (enctype = "BASE64", line_length = 76, bytes = 19472)
`pragma protect data_block
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
`pragma protect end_protected
`ifndef GLBL
`define GLBL
`timescale  1 ps / 1 ps

module glbl ();

    parameter ROC_WIDTH = 100000;
    parameter TOC_WIDTH = 0;
    parameter GRES_WIDTH = 10000;
    parameter GRES_START = 10000;

//--------   STARTUP Globals --------------
    wire GSR;
    wire GTS;
    wire GWE;
    wire PRLD;
    wire GRESTORE;
    tri1 p_up_tmp;
    tri (weak1, strong0) PLL_LOCKG = p_up_tmp;

    wire PROGB_GLBL;
    wire CCLKO_GLBL;
    wire FCSBO_GLBL;
    wire [3:0] DO_GLBL;
    wire [3:0] DI_GLBL;
   
    reg GSR_int;
    reg GTS_int;
    reg PRLD_int;
    reg GRESTORE_int;

//--------   JTAG Globals --------------
    wire JTAG_TDO_GLBL;
    wire JTAG_TCK_GLBL;
    wire JTAG_TDI_GLBL;
    wire JTAG_TMS_GLBL;
    wire JTAG_TRST_GLBL;

    reg JTAG_CAPTURE_GLBL;
    reg JTAG_RESET_GLBL;
    reg JTAG_SHIFT_GLBL;
    reg JTAG_UPDATE_GLBL;
    reg JTAG_RUNTEST_GLBL;

    reg JTAG_SEL1_GLBL = 0;
    reg JTAG_SEL2_GLBL = 0 ;
    reg JTAG_SEL3_GLBL = 0;
    reg JTAG_SEL4_GLBL = 0;

    reg JTAG_USER_TDO1_GLBL = 1'bz;
    reg JTAG_USER_TDO2_GLBL = 1'bz;
    reg JTAG_USER_TDO3_GLBL = 1'bz;
    reg JTAG_USER_TDO4_GLBL = 1'bz;

    assign (strong1, weak0) GSR = GSR_int;
    assign (strong1, weak0) GTS = GTS_int;
    assign (weak1, weak0) PRLD = PRLD_int;
    assign (strong1, weak0) GRESTORE = GRESTORE_int;

    initial begin
	GSR_int = 1'b1;
	PRLD_int = 1'b1;
	#(ROC_WIDTH)
	GSR_int = 1'b0;
	PRLD_int = 1'b0;
    end

    initial begin
	GTS_int = 1'b1;
	#(TOC_WIDTH)
	GTS_int = 1'b0;
    end

    initial begin 
	GRESTORE_int = 1'b0;
	#(GRES_START);
	GRESTORE_int = 1'b1;
	#(GRES_WIDTH);
	GRESTORE_int = 1'b0;
    end

endmodule
`endif
