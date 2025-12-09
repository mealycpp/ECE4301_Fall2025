// Copyright 1986-2020 Xilinx, Inc. All Rights Reserved.
// --------------------------------------------------------------------------------
// Tool Version: Vivado v.2020.2 (win64) Build 3064766 Wed Nov 18 09:12:45 MST 2020
// Date        : Tue Dec  2 13:47:38 2025
// Host        : MSI running 64-bit major release  (build 9200)
// Command     : write_verilog -force -mode funcsim
//               c:/ECE/4300/ECE4300_FALL2025/Group-B/VexRiscv_Test/VexRiscv_Test.gen/sources_1/ip/blk_mem_gen_0/blk_mem_gen_0_sim_netlist.v
// Design      : blk_mem_gen_0
// Purpose     : This verilog netlist is a functional simulation representation of the design and should not be modified
//               or synthesized. This netlist cannot be used for SDF annotated simulation.
// Device      : xc7a100tcsg324-1
// --------------------------------------------------------------------------------
`timescale 1 ps / 1 ps

(* CHECK_LICENSE_TYPE = "blk_mem_gen_0,blk_mem_gen_v8_4_4,{}" *) (* downgradeipidentifiedwarnings = "yes" *) (* x_core_info = "blk_mem_gen_v8_4_4,Vivado 2020.2" *) 
(* NotValidForBitStream *)
module blk_mem_gen_0
   (clka,
    ena,
    addra,
    douta);
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA CLK" *) (* x_interface_parameter = "XIL_INTERFACENAME BRAM_PORTA, MEM_SIZE 8192, MEM_WIDTH 32, MEM_ECC NONE, MASTER_TYPE OTHER, READ_LATENCY 1" *) input clka;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA EN" *) input ena;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA ADDR" *) input [3:0]addra;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA DOUT" *) output [31:0]douta;

  wire [3:0]addra;
  wire clka;
  wire [31:0]douta;
  wire ena;
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
  (* C_EST_POWER_SUMMARY = "Estimated Power for IP     :     3.375199 mW" *) 
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
  (* C_INIT_FILE = "blk_mem_gen_0.mem" *) 
  (* C_INIT_FILE_NAME = "blk_mem_gen_0.mif" *) 
  (* C_INTERFACE_TYPE = "0" *) 
  (* C_LOAD_INIT_FILE = "1" *) 
  (* C_MEM_TYPE = "3" *) 
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
  blk_mem_gen_0_blk_mem_gen_v8_4_4 U0
       (.addra(addra),
        .addrb({1'b0,1'b0,1'b0,1'b0}),
        .clka(clka),
        .clkb(1'b0),
        .dbiterr(NLW_U0_dbiterr_UNCONNECTED),
        .deepsleep(1'b0),
        .dina({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
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
        .wea(1'b0),
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
`pragma protect encoding = (enctype = "BASE64", line_length = 76, bytes = 18912)
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
