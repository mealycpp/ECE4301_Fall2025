vlib questa_lib/work
vlib questa_lib/msim

vlib questa_lib/msim/xilinx_vip
vlib questa_lib/msim/xpm
vlib questa_lib/msim/xil_defaultlib
vlib questa_lib/msim/axi_infrastructure_v1_1_0
vlib questa_lib/msim/axi_vip_v1_1_22
vlib questa_lib/msim/processing_system7_vip_v1_0_24
vlib questa_lib/msim/proc_sys_reset_v5_0_17
vlib questa_lib/msim/smartconnect_v1_0
vlib questa_lib/msim/axi_register_slice_v2_1_36
vlib questa_lib/msim/axi_lite_ipif_v3_0_4
vlib questa_lib/msim/interrupt_control_v3_1_5
vlib questa_lib/msim/axi_gpio_v2_0_37
vlib questa_lib/msim/axi_bram_ctrl_v4_1_13
vlib questa_lib/msim/blk_mem_gen_v8_4_12

vmap xilinx_vip questa_lib/msim/xilinx_vip
vmap xpm questa_lib/msim/xpm
vmap xil_defaultlib questa_lib/msim/xil_defaultlib
vmap axi_infrastructure_v1_1_0 questa_lib/msim/axi_infrastructure_v1_1_0
vmap axi_vip_v1_1_22 questa_lib/msim/axi_vip_v1_1_22
vmap processing_system7_vip_v1_0_24 questa_lib/msim/processing_system7_vip_v1_0_24
vmap proc_sys_reset_v5_0_17 questa_lib/msim/proc_sys_reset_v5_0_17
vmap smartconnect_v1_0 questa_lib/msim/smartconnect_v1_0
vmap axi_register_slice_v2_1_36 questa_lib/msim/axi_register_slice_v2_1_36
vmap axi_lite_ipif_v3_0_4 questa_lib/msim/axi_lite_ipif_v3_0_4
vmap interrupt_control_v3_1_5 questa_lib/msim/interrupt_control_v3_1_5
vmap axi_gpio_v2_0_37 questa_lib/msim/axi_gpio_v2_0_37
vmap axi_bram_ctrl_v4_1_13 questa_lib/msim/axi_bram_ctrl_v4_1_13
vmap blk_mem_gen_v8_4_12 questa_lib/msim/blk_mem_gen_v8_4_12

vlog -work xilinx_vip -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/axi4stream_vip_axi4streampc.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/axi_vip_axi4pc.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/xil_common_vip_pkg.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/axi4stream_vip_pkg.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/axi_vip_pkg.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/axi4stream_vip_if.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/axi_vip_if.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/clk_vip_if.sv" \
"/opt/Xilinx/2025.2/data/xilinx_vip/hdl/rst_vip_if.sv" \

vlog -work xpm -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"/opt/Xilinx/2025.2/data/ip/xpm/xpm_cdc/hdl/xpm_cdc.sv" \
"/opt/Xilinx/2025.2/data/ip/xpm/xpm_fifo/hdl/xpm_fifo.sv" \
"/opt/Xilinx/2025.2/data/ip/xpm/xpm_memory/hdl/xpm_memory.sv" \

vcom -work xpm -64 -93  \
"/opt/Xilinx/2025.2/data/ip/xpm/xpm_VCOMP.vhd" \

vlog -work xil_defaultlib -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.srcs/sources_1/new/poseidon_stub.v" \

vlog -work axi_infrastructure_v1_1_0 -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl/axi_infrastructure_v1_1_vl_rfs.v" \

vlog -work axi_vip_v1_1_22 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/b16a/hdl/axi_vip_v1_1_vl_rfs.sv" \

vlog -work processing_system7_vip_v1_0_24 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl/processing_system7_vip_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_processing_system7_0_1/sim/poseidon_block_processing_system7_0_1.v" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/sim/bd_8597.v" \

vcom -work proc_sys_reset_v5_0_17 -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9438/hdl/proc_sys_reset_v5_0_vh_rfs.vhd" \

vcom -work xil_defaultlib -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_1/sim/bd_8597_psr_aclk_0.vhd" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/sc_util_v1_0_vl_rfs.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/0848/hdl/sc_switchboard_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_2/sim/bd_8597_arsw_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_3/sim/bd_8597_rsw_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_4/sim/bd_8597_awsw_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_5/sim/bd_8597_wsw_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_6/sim/bd_8597_bsw_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/3d9a/hdl/sc_mmu_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_7/sim/bd_8597_s00mmu_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/7785/hdl/sc_transaction_regulator_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_8/sim/bd_8597_s00tr_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/3051/hdl/sc_si_converter_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_9/sim/bd_8597_s00sic_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/852f/hdl/sc_axi2sc_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_10/sim/bd_8597_s00a2s_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/sc_node_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_11/sim/bd_8597_sarn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_12/sim/bd_8597_srn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_13/sim/bd_8597_sawn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_14/sim/bd_8597_swn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_15/sim/bd_8597_sbn_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/fca9/hdl/sc_sc2axi_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_16/sim/bd_8597_m00s2a_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_17/sim/bd_8597_m00arn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_18/sim/bd_8597_m00rn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_19/sim/bd_8597_m00awn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_20/sim/bd_8597_m00wn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_21/sim/bd_8597_m00bn_0.sv" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/e44a/hdl/sc_exit_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_22/sim/bd_8597_m00e_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_23/sim/bd_8597_m01s2a_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_24/sim/bd_8597_m01arn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_25/sim/bd_8597_m01rn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_26/sim/bd_8597_m01awn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_27/sim/bd_8597_m01wn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_28/sim/bd_8597_m01bn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_29/sim/bd_8597_m01e_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_30/sim/bd_8597_m02s2a_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_31/sim/bd_8597_m02arn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_32/sim/bd_8597_m02rn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_33/sim/bd_8597_m02awn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_34/sim/bd_8597_m02wn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_35/sim/bd_8597_m02bn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_36/sim/bd_8597_m02e_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_37/sim/bd_8597_m03s2a_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_38/sim/bd_8597_m03arn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_39/sim/bd_8597_m03rn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_40/sim/bd_8597_m03awn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_41/sim/bd_8597_m03wn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_42/sim/bd_8597_m03bn_0.sv" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/bd_0/ip/ip_43/sim/bd_8597_m03e_0.sv" \

vcom -work smartconnect_v1_0 -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/cb42/hdl/sc_ultralite_v1_0_rfs.vhd" \

vlog -work smartconnect_v1_0 -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/cb42/hdl/sc_ultralite_v1_0_rfs.sv" \

vlog -work axi_register_slice_v2_1_36 -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/bc4b/hdl/axi_register_slice_v2_1_vl_rfs.v" \

vlog -work xil_defaultlib -64 -incr -mfcu  -sv -L axi_vip_v1_1_22 -L processing_system7_vip_v1_0_24 -L smartconnect_v1_0 -L xilinx_vip "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_smartconnect_0_1/sim/poseidon_block_smartconnect_0_1.sv" \

vlog -work xil_defaultlib -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_poseidon_accel_axi_l_0_0/sim/poseidon_block_poseidon_accel_axi_l_0_0.v" \

vcom -work axi_lite_ipif_v3_0_4 -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/66ea/hdl/axi_lite_ipif_v3_0_vh_rfs.vhd" \

vcom -work interrupt_control_v3_1_5 -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/d8cc/hdl/interrupt_control_v3_1_vh_rfs.vhd" \

vcom -work axi_gpio_v2_0_37 -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/0271/hdl/axi_gpio_v2_0_vh_rfs.vhd" \

vcom -work xil_defaultlib -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_axi_gpio_0_1/sim/poseidon_block_axi_gpio_0_1.vhd" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_leds_0/sim/poseidon_block_leds_0.vhd" \

vcom -work axi_bram_ctrl_v4_1_13 -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/2f03/hdl/axi_bram_ctrl_v4_1_rfs.vhd" \

vcom -work xil_defaultlib -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_axi_bram_ctrl_0_0/sim/poseidon_block_axi_bram_ctrl_0_0.vhd" \

vlog -work blk_mem_gen_v8_4_12 -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/42f3/simulation/blk_mem_gen_v8_4.v" \

vlog -work xil_defaultlib -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_axi_bram_ctrl_0_bram_0/sim/poseidon_block_axi_bram_ctrl_0_bram_0.v" \

vcom -work xil_defaultlib -64 -93  \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ip/poseidon_block_rst_ps7_0_100M_0/sim/poseidon_block_rst_ps7_0_100M_0.vhd" \

vlog -work xil_defaultlib -64 -incr -mfcu  "+incdir+../../../../../../../../../opt/Xilinx/2025.2/data/rsb/busdef" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/ec67/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/9a25/hdl" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/f0b6/hdl/verilog" "+incdir+../../../poseidon_bench.gen/sources_1/bd/poseidon_block/ipshared/00fe/hdl/verilog" "+incdir+/opt/Xilinx/2025.2/data/xilinx_vip/include" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/sim/poseidon_block.v" \
"../../../poseidon_bench.gen/sources_1/bd/poseidon_block/hdl/poseidon_block_wrapper.v" \

vlog -work xil_defaultlib \
"glbl.v"

