/*

Copyright (c) 2020 Alex Forencich - Modified for dual-port bidirectional ASCON

*/

// Language: Verilog 2001

`resetall
`timescale 1ns / 1ps
`default_nettype none

/*
 * FPGA1 core logic - Dual Ethernet Port Bidirectional ASCON
 *
 * ENET0 (PLC/PC side, plaintext, noktadan noktaya):
 *   RX: PLC'den plaintext alır → encrypt → ENET1 TX
 *   TX: Decrypt çıkışını PLC'ye gönderir ← decrypt ← ENET1 RX
 *
 * ENET1 (Network side, encrypted):
 *   TX: Şifreli veriyi ağa gönderir (encrypt çıkışı)
 *   RX: Ağdan şifreli veri alır → decrypt → ENET0 TX
 *
 * Data paths:
 *   Encrypt: ENET0 RX → FIFO → ASCON encrypt → FIFO → ENET1 TX
 *   Decrypt: ENET1 RX → FIFO → ASCON decrypt → FIFO → ENET0 TX
 */
module fpga_core #
(
    parameter TARGET = "GENERIC"
)
(
    input  wire       clk,       // 125 MHz
    input  wire       clk90,     // 125 MHz + 90 deg
    input  wire       clk_slow,  // 62.5 MHz
    input  wire       rst,       // 125 MHz domain reset
    input  wire       rst_slow,  // 62.5 MHz domain reset

    input  wire [3:0]  btn,
    input  wire [17:0] sw,
    output wire [8:0]  ledg,
    output wire [17:0] ledr,
    output wire [6:0]  hex0,
    output wire [6:0]  hex1,
    output wire [6:0]  hex2,
    output wire [6:0]  hex3,
    output wire [6:0]  hex4,
    output wire [6:0]  hex5,
    output wire [6:0]  hex6,
    output wire [6:0]  hex7,
    output wire [35:0] gpio,

    // ENET0 — PLC/PC side (plaintext)
    input  wire       phy0_rx_clk,
    input  wire [3:0] phy0_rxd,
    input  wire       phy0_rx_ctl,
    output wire       phy0_tx_clk,
    output wire [3:0] phy0_txd,
    output wire       phy0_tx_ctl,
    output wire       phy0_reset_n,
    input  wire       phy0_int_n,

    // ENET1 — Network side (encrypted)
    input  wire       phy1_rx_clk,
    input  wire [3:0] phy1_rxd,
    input  wire       phy1_rx_ctl,
    output wire       phy1_tx_clk,
    output wire [3:0] phy1_txd,
    output wire       phy1_tx_ctl,
    output wire       phy1_reset_n,
    input  wire       phy1_int_n
);

// ================================================================
// Network Configuration
// ================================================================
// ENET0: Plaintext side (PLC/PC bağlantısı, izole subnet)
localparam [47:0] LOCAL_MAC_0   = 48'h02_00_00_00_00_00;
localparam [31:0] LOCAL_IP_0    = {8'd10, 8'd0, 8'd0, 8'd1};      // 10.0.0.1
localparam [31:0] GATEWAY_IP_0  = {8'd10, 8'd0, 8'd0, 8'd1};
localparam [31:0] SUBNET_MASK_0 = {8'd255, 8'd255, 8'd255, 8'd0};

// ENET1: Encrypted side (ağ tarafı)
localparam [47:0] LOCAL_MAC_1   = 48'h02_00_00_00_00_01;
localparam [31:0] LOCAL_IP_1    = {8'd192, 8'd168, 8'd1, 8'd128};  // 192.168.1.128
localparam [31:0] GATEWAY_IP_1  = {8'd192, 8'd168, 8'd1, 8'd1};
localparam [31:0] SUBNET_MASK_1 = {8'd255, 8'd255, 8'd255, 8'd0};

// Hedef adresler
localparam [31:0] FPGA2_IP      = {8'd192, 8'd168, 8'd1, 8'd129};  // 192.168.1.129
localparam [31:0] PLC_IP        = {8'd10, 8'd0, 8'd0, 8'd2};       // 10.0.0.2 (PLC/PC)
localparam [15:0] UDP_PORT      = 16'd1234;

// ================================================================
// ENET0 wires (PLC/PC side — plaintext)
// ================================================================
wire [7:0] e0_rx_axis_tdata, e0_tx_axis_tdata;
wire e0_rx_axis_tvalid, e0_rx_axis_tready, e0_rx_axis_tlast, e0_rx_axis_tuser;
wire e0_tx_axis_tvalid, e0_tx_axis_tready, e0_tx_axis_tlast, e0_tx_axis_tuser;

wire e0_rx_eth_hdr_valid, e0_rx_eth_hdr_ready;
wire [47:0] e0_rx_eth_dest_mac, e0_rx_eth_src_mac;
wire [15:0] e0_rx_eth_type;
wire [7:0] e0_rx_eth_payload_tdata;
wire e0_rx_eth_payload_tvalid, e0_rx_eth_payload_tready, e0_rx_eth_payload_tlast, e0_rx_eth_payload_tuser;

wire e0_tx_eth_hdr_valid, e0_tx_eth_hdr_ready;
wire [47:0] e0_tx_eth_dest_mac, e0_tx_eth_src_mac;
wire [15:0] e0_tx_eth_type;
wire [7:0] e0_tx_eth_payload_tdata;
wire e0_tx_eth_payload_tvalid, e0_tx_eth_payload_tready, e0_tx_eth_payload_tlast, e0_tx_eth_payload_tuser;

wire e0_rx_ip_hdr_valid, e0_rx_ip_hdr_ready;
wire [47:0] e0_rx_ip_eth_dest_mac, e0_rx_ip_eth_src_mac;
wire [15:0] e0_rx_ip_eth_type;
wire [3:0] e0_rx_ip_version, e0_rx_ip_ihl;
wire [5:0] e0_rx_ip_dscp;
wire [1:0] e0_rx_ip_ecn;
wire [15:0] e0_rx_ip_length, e0_rx_ip_identification;
wire [2:0] e0_rx_ip_flags;
wire [12:0] e0_rx_ip_fragment_offset;
wire [7:0] e0_rx_ip_ttl, e0_rx_ip_protocol;
wire [15:0] e0_rx_ip_header_checksum;
wire [31:0] e0_rx_ip_source_ip, e0_rx_ip_dest_ip;
wire [7:0] e0_rx_ip_payload_tdata;
wire e0_rx_ip_payload_tvalid, e0_rx_ip_payload_tready, e0_rx_ip_payload_tlast, e0_rx_ip_payload_tuser;

wire e0_rx_udp_hdr_valid, e0_rx_udp_hdr_ready;
wire [47:0] e0_rx_udp_eth_dest_mac, e0_rx_udp_eth_src_mac;
wire [15:0] e0_rx_udp_eth_type;
wire [3:0] e0_rx_udp_ip_version, e0_rx_udp_ip_ihl;
wire [5:0] e0_rx_udp_ip_dscp;
wire [1:0] e0_rx_udp_ip_ecn;
wire [15:0] e0_rx_udp_ip_length, e0_rx_udp_ip_identification;
wire [2:0] e0_rx_udp_ip_flags;
wire [12:0] e0_rx_udp_ip_fragment_offset;
wire [7:0] e0_rx_udp_ip_ttl, e0_rx_udp_ip_protocol;
wire [15:0] e0_rx_udp_ip_header_checksum;
wire [31:0] e0_rx_udp_ip_source_ip, e0_rx_udp_ip_dest_ip;
wire [15:0] e0_rx_udp_source_port, e0_rx_udp_dest_port;
wire [15:0] e0_rx_udp_length, e0_rx_udp_checksum;
wire [7:0] e0_rx_udp_payload_tdata;
wire e0_rx_udp_payload_tvalid, e0_rx_udp_payload_tready, e0_rx_udp_payload_tlast, e0_rx_udp_payload_tuser;

wire e0_tx_udp_hdr_valid, e0_tx_udp_hdr_ready;
wire [5:0] e0_tx_udp_ip_dscp;
wire [1:0] e0_tx_udp_ip_ecn;
wire [7:0] e0_tx_udp_ip_ttl;
wire [31:0] e0_tx_udp_ip_source_ip, e0_tx_udp_ip_dest_ip;
wire [15:0] e0_tx_udp_source_port, e0_tx_udp_dest_port;
wire [15:0] e0_tx_udp_length, e0_tx_udp_checksum;
wire [7:0] e0_tx_udp_payload_tdata;
wire e0_tx_udp_payload_tvalid, e0_tx_udp_payload_tready, e0_tx_udp_payload_tlast, e0_tx_udp_payload_tuser;

// ================================================================
// ENET1 wires (Network side — encrypted)
// ================================================================
wire [7:0] e1_rx_axis_tdata, e1_tx_axis_tdata;
wire e1_rx_axis_tvalid, e1_rx_axis_tready, e1_rx_axis_tlast, e1_rx_axis_tuser;
wire e1_tx_axis_tvalid, e1_tx_axis_tready, e1_tx_axis_tlast, e1_tx_axis_tuser;

wire e1_rx_eth_hdr_valid, e1_rx_eth_hdr_ready;
wire [47:0] e1_rx_eth_dest_mac, e1_rx_eth_src_mac;
wire [15:0] e1_rx_eth_type;
wire [7:0] e1_rx_eth_payload_tdata;
wire e1_rx_eth_payload_tvalid, e1_rx_eth_payload_tready, e1_rx_eth_payload_tlast, e1_rx_eth_payload_tuser;

wire e1_tx_eth_hdr_valid, e1_tx_eth_hdr_ready;
wire [47:0] e1_tx_eth_dest_mac, e1_tx_eth_src_mac;
wire [15:0] e1_tx_eth_type;
wire [7:0] e1_tx_eth_payload_tdata;
wire e1_tx_eth_payload_tvalid, e1_tx_eth_payload_tready, e1_tx_eth_payload_tlast, e1_tx_eth_payload_tuser;

wire e1_rx_ip_hdr_valid, e1_rx_ip_hdr_ready;
wire [47:0] e1_rx_ip_eth_dest_mac, e1_rx_ip_eth_src_mac;
wire [15:0] e1_rx_ip_eth_type;
wire [3:0] e1_rx_ip_version, e1_rx_ip_ihl;
wire [5:0] e1_rx_ip_dscp;
wire [1:0] e1_rx_ip_ecn;
wire [15:0] e1_rx_ip_length, e1_rx_ip_identification;
wire [2:0] e1_rx_ip_flags;
wire [12:0] e1_rx_ip_fragment_offset;
wire [7:0] e1_rx_ip_ttl, e1_rx_ip_protocol;
wire [15:0] e1_rx_ip_header_checksum;
wire [31:0] e1_rx_ip_source_ip, e1_rx_ip_dest_ip;
wire [7:0] e1_rx_ip_payload_tdata;
wire e1_rx_ip_payload_tvalid, e1_rx_ip_payload_tready, e1_rx_ip_payload_tlast, e1_rx_ip_payload_tuser;

wire e1_rx_udp_hdr_valid, e1_rx_udp_hdr_ready;
wire [47:0] e1_rx_udp_eth_dest_mac, e1_rx_udp_eth_src_mac;
wire [15:0] e1_rx_udp_eth_type;
wire [3:0] e1_rx_udp_ip_version, e1_rx_udp_ip_ihl;
wire [5:0] e1_rx_udp_ip_dscp;
wire [1:0] e1_rx_udp_ip_ecn;
wire [15:0] e1_rx_udp_ip_length, e1_rx_udp_ip_identification;
wire [2:0] e1_rx_udp_ip_flags;
wire [12:0] e1_rx_udp_ip_fragment_offset;
wire [7:0] e1_rx_udp_ip_ttl, e1_rx_udp_ip_protocol;
wire [15:0] e1_rx_udp_ip_header_checksum;
wire [31:0] e1_rx_udp_ip_source_ip, e1_rx_udp_ip_dest_ip;
wire [15:0] e1_rx_udp_source_port, e1_rx_udp_dest_port;
wire [15:0] e1_rx_udp_length, e1_rx_udp_checksum;
wire [7:0] e1_rx_udp_payload_tdata;
wire e1_rx_udp_payload_tvalid, e1_rx_udp_payload_tready, e1_rx_udp_payload_tlast, e1_rx_udp_payload_tuser;

wire e1_tx_udp_hdr_valid, e1_tx_udp_hdr_ready;
wire [5:0] e1_tx_udp_ip_dscp;
wire [1:0] e1_tx_udp_ip_ecn;
wire [7:0] e1_tx_udp_ip_ttl;
wire [31:0] e1_tx_udp_ip_source_ip, e1_tx_udp_ip_dest_ip;
wire [15:0] e1_tx_udp_source_port, e1_tx_udp_dest_port;
wire [15:0] e1_tx_udp_length, e1_tx_udp_checksum;
wire [7:0] e1_tx_udp_payload_tdata;
wire e1_tx_udp_payload_tvalid, e1_tx_udp_payload_tready, e1_tx_udp_payload_tlast, e1_tx_udp_payload_tuser;

// ================================================================
// ENCRYPT path wires (ENET0 RX → encrypt → ENET1 TX)
// ================================================================
wire [7:0] enc_rx_filt_tdata;
wire enc_rx_filt_tvalid, enc_rx_filt_tready, enc_rx_filt_tlast;

wire [7:0] enc_slow_rx_tdata;
wire enc_slow_rx_tvalid, enc_slow_rx_tready, enc_slow_rx_tlast;

wire [7:0] enc_slow_tx_tdata;
wire enc_slow_tx_tvalid, enc_slow_tx_tready, enc_slow_tx_tlast;

wire [7:0] enc_out_tdata;
wire enc_out_tvalid, enc_out_tready, enc_out_tlast;

// ================================================================
// DECRYPT path wires (ENET1 RX → decrypt → ENET0 TX)
// ================================================================
wire [7:0] dec_rx_filt_tdata;
wire dec_rx_filt_tvalid, dec_rx_filt_tready, dec_rx_filt_tlast;

wire [7:0] dec_slow_rx_tdata;
wire dec_slow_rx_tvalid, dec_slow_rx_tready, dec_slow_rx_tlast;

wire [7:0] dec_slow_tx_tdata;
wire dec_slow_tx_tvalid, dec_slow_tx_tready, dec_slow_tx_tlast;

wire [7:0] dec_out_tdata;
wire dec_out_tvalid, dec_out_tready, dec_out_tlast;

// ================================================================
// ENET0/ENET1: IP ports not used
// ================================================================
assign e0_rx_ip_hdr_ready = 1;
assign e0_rx_ip_payload_tready = 1;
assign e1_rx_ip_hdr_ready = 1;
assign e1_rx_ip_payload_tready = 1;

// ================================================================
// ENCRYPT PATH: ENET0 RX port matching (port 1234)
// PLC/PC'den gelen plaintext → encrypt'e yönlendirilir
// ================================================================
wire e0_match_cond = e0_rx_udp_dest_port == UDP_PORT;
wire e0_no_match   = !e0_match_cond;

reg e0_match_cond_reg = 0;
reg e0_no_match_reg = 0;

always @(posedge clk) begin
    if (rst) begin
        e0_match_cond_reg <= 0;
        e0_no_match_reg <= 0;
    end else begin
        if (e0_rx_udp_payload_tvalid) begin
            if ((!e0_match_cond_reg && !e0_no_match_reg) ||
                (e0_rx_udp_payload_tvalid && e0_rx_udp_payload_tready && e0_rx_udp_payload_tlast)) begin
                e0_match_cond_reg <= e0_match_cond;
                e0_no_match_reg   <= e0_no_match;
            end
        end else begin
            e0_match_cond_reg <= 0;
            e0_no_match_reg <= 0;
        end
    end
end

assign enc_rx_filt_tdata  = e0_rx_udp_payload_tdata;
assign enc_rx_filt_tvalid = e0_rx_udp_payload_tvalid && e0_match_cond_reg;
assign e0_rx_udp_payload_tready = (enc_rx_filt_tready && e0_match_cond_reg) || e0_no_match_reg;
assign enc_rx_filt_tlast  = e0_rx_udp_payload_tlast;

assign e0_rx_udp_hdr_ready = (!enc_hdr_pending && !enc_hdr_sent && e0_match_cond) || e0_no_match;

// ================================================================
// ENCRYPT PATH: Header latch (ENET0 RX → ENET1 TX)
// ================================================================
reg [15:0] enc_latched_udp_length = 0;
reg        enc_hdr_pending = 0;
reg        enc_hdr_sent = 0;

always @(posedge clk) begin
    if (rst) begin
        enc_latched_udp_length <= 0;
        enc_hdr_pending        <= 0;
        enc_hdr_sent           <= 0;
    end else begin
        if (e0_rx_udp_hdr_valid && e0_match_cond && !enc_hdr_pending && !enc_hdr_sent) begin
            enc_latched_udp_length <= e0_rx_udp_length;
            enc_hdr_pending        <= 1;
        end
        if (enc_hdr_pending && enc_out_tvalid && e1_tx_udp_hdr_ready) begin
            enc_hdr_pending <= 0;
            enc_hdr_sent    <= 1;
        end
        if (enc_hdr_sent && enc_out_tvalid && enc_out_tready && enc_out_tlast) begin
            enc_hdr_sent <= 0;
        end
    end
end

// ENET1 TX: encrypted output → FPGA2
assign e1_tx_udp_hdr_valid    = enc_hdr_pending && enc_out_tvalid;
assign e1_tx_udp_ip_dscp      = 0;
assign e1_tx_udp_ip_ecn       = 0;
assign e1_tx_udp_ip_ttl       = 64;
assign e1_tx_udp_ip_source_ip = LOCAL_IP_1;             // 192.168.1.128
assign e1_tx_udp_ip_dest_ip   = FPGA2_IP;               // 192.168.1.129
assign e1_tx_udp_source_port  = UDP_PORT;
assign e1_tx_udp_dest_port    = UDP_PORT;
assign e1_tx_udp_length       = enc_latched_udp_length + 16'd36;
assign e1_tx_udp_checksum     = 0;

assign e1_tx_udp_payload_tdata  = enc_out_tdata;
assign e1_tx_udp_payload_tvalid = enc_hdr_sent ? enc_out_tvalid : 1'b0;
assign enc_out_tready            = enc_hdr_sent ? e1_tx_udp_payload_tready : 1'b0;
assign e1_tx_udp_payload_tlast  = enc_out_tlast;
assign e1_tx_udp_payload_tuser  = 1'b0;

// ================================================================
// DECRYPT PATH: ENET1 RX port matching (port 1234)
// Ağdan gelen şifreli veri → decrypt'e yönlendirilir
// ================================================================
wire e1_match_cond = e1_rx_udp_dest_port == UDP_PORT;
wire e1_no_match   = !e1_match_cond;

reg e1_match_cond_reg = 0;
reg e1_no_match_reg = 0;

always @(posedge clk) begin
    if (rst) begin
        e1_match_cond_reg <= 0;
        e1_no_match_reg <= 0;
    end else begin
        if (e1_rx_udp_payload_tvalid) begin
            if ((!e1_match_cond_reg && !e1_no_match_reg) ||
                (e1_rx_udp_payload_tvalid && e1_rx_udp_payload_tready && e1_rx_udp_payload_tlast)) begin
                e1_match_cond_reg <= e1_match_cond;
                e1_no_match_reg   <= e1_no_match;
            end
        end else begin
            e1_match_cond_reg <= 0;
            e1_no_match_reg <= 0;
        end
    end
end

assign dec_rx_filt_tdata  = e1_rx_udp_payload_tdata;
assign dec_rx_filt_tvalid = e1_rx_udp_payload_tvalid && e1_match_cond_reg;
assign e1_rx_udp_payload_tready = (dec_rx_filt_tready && e1_match_cond_reg) || e1_no_match_reg;
assign dec_rx_filt_tlast  = e1_rx_udp_payload_tlast;

assign e1_rx_udp_hdr_ready = (!dec_hdr_pending && !dec_hdr_sent && e1_match_cond) || e1_no_match;

// ================================================================
// DECRYPT PATH: Header latch (ENET1 RX → ENET0 TX)
// Decrypt çıkışı sadece plaintext (nonce/AD/tag yok), boyut: original - 36
// ================================================================
reg [15:0] dec_latched_udp_length = 0;
reg        dec_hdr_pending = 0;
reg        dec_hdr_sent = 0;

always @(posedge clk) begin
    if (rst) begin
        dec_latched_udp_length <= 0;
        dec_hdr_pending        <= 0;
        dec_hdr_sent           <= 0;
    end else begin
        if (e1_rx_udp_hdr_valid && e1_match_cond && !dec_hdr_pending && !dec_hdr_sent) begin
            dec_latched_udp_length <= e1_rx_udp_length;
            dec_hdr_pending        <= 1;
        end
        if (dec_hdr_pending && dec_out_tvalid && e0_tx_udp_hdr_ready) begin
            dec_hdr_pending <= 0;
            dec_hdr_sent    <= 1;
        end
        if (dec_hdr_sent && dec_out_tvalid && dec_out_tready && dec_out_tlast) begin
            dec_hdr_sent <= 0;
        end
    end
end

// ENET0 TX: decrypted plaintext → PLC/PC
assign e0_tx_udp_hdr_valid    = dec_hdr_pending && dec_out_tvalid;
assign e0_tx_udp_ip_dscp      = 0;
assign e0_tx_udp_ip_ecn       = 0;
assign e0_tx_udp_ip_ttl       = 64;
assign e0_tx_udp_ip_source_ip = LOCAL_IP_0;              // 10.0.0.1
assign e0_tx_udp_ip_dest_ip   = PLC_IP;                  // 10.0.0.2
assign e0_tx_udp_source_port  = UDP_PORT;
assign e0_tx_udp_dest_port    = UDP_PORT;
// Decrypt çıkışı = original_length - 36 (nonce+AD+tag çıkarılmış)
assign e0_tx_udp_length       = dec_latched_udp_length - 16'd36;
assign e0_tx_udp_checksum     = 0;

assign e0_tx_udp_payload_tdata  = dec_out_tdata;
assign e0_tx_udp_payload_tvalid = dec_hdr_sent ? dec_out_tvalid : 1'b0;
assign dec_out_tready            = dec_hdr_sent ? e0_tx_udp_payload_tready : 1'b0;
assign e0_tx_udp_payload_tlast  = dec_out_tlast;
assign e0_tx_udp_payload_tuser  = 1'b0;

// ================================================================
// LED displays
// ================================================================
reg valid_last = 0;
reg [7:0] led_reg = 0;

always @(posedge clk) begin
    if (e1_tx_udp_payload_tvalid) begin
        if (!valid_last) begin
            led_reg <= e1_tx_udp_payload_tdata;
            valid_last <= 1'b1;
        end
        if (e1_tx_udp_payload_tlast)
            valid_last <= 1'b0;
    end
    if (rst) led_reg <= 0;
end

reg [31:0] dest_ip_reg = 0;
always @(posedge clk) begin
    if (e1_tx_udp_hdr_valid && e1_tx_udp_hdr_ready)
        dest_ip_reg <= e1_tx_udp_ip_dest_ip;
    if (rst) dest_ip_reg <= 0;
end

hex_display #(.INVERT(1)) hex_display_0 (.in(dest_ip_reg[3:0]),   .enable(1), .out(hex0));
hex_display #(.INVERT(1)) hex_display_1 (.in(dest_ip_reg[7:4]),   .enable(1), .out(hex1));
hex_display #(.INVERT(1)) hex_display_2 (.in(dest_ip_reg[11:8]),  .enable(1), .out(hex2));
hex_display #(.INVERT(1)) hex_display_3 (.in(dest_ip_reg[15:12]), .enable(1), .out(hex3));
hex_display #(.INVERT(1)) hex_display_4 (.in(dest_ip_reg[19:16]), .enable(1), .out(hex4));
hex_display #(.INVERT(1)) hex_display_5 (.in(dest_ip_reg[23:20]), .enable(1), .out(hex5));
hex_display #(.INVERT(1)) hex_display_6 (.in(dest_ip_reg[27:24]), .enable(1), .out(hex6));
hex_display #(.INVERT(1)) hex_display_7 (.in(dest_ip_reg[31:28]), .enable(1), .out(hex7));

assign ledg = led_reg;
assign ledr = sw;
assign phy0_reset_n = ~rst;
assign phy1_reset_n = ~rst;
assign gpio = 0;

// ================================================================
// ENET0: Ethernet MAC (PLC/PC side — plaintext)
// ================================================================
eth_mac_1g_rgmii_fifo #(
    .TARGET(TARGET), .USE_CLK90("TRUE"), .ENABLE_PADDING(1),
    .MIN_FRAME_LENGTH(64), .TX_FIFO_DEPTH(2048), .TX_FRAME_FIFO(1),
    .RX_FIFO_DEPTH(2048), .RX_FRAME_FIFO(1)
)
eth_mac_0 (
    .gtx_clk(clk), .gtx_clk90(clk90), .gtx_rst(rst),
    .logic_clk(clk), .logic_rst(rst),
    .tx_axis_tdata(e0_tx_axis_tdata), .tx_axis_tvalid(e0_tx_axis_tvalid),
    .tx_axis_tready(e0_tx_axis_tready), .tx_axis_tlast(e0_tx_axis_tlast),
    .tx_axis_tuser(e0_tx_axis_tuser),
    .rx_axis_tdata(e0_rx_axis_tdata), .rx_axis_tvalid(e0_rx_axis_tvalid),
    .rx_axis_tready(e0_rx_axis_tready), .rx_axis_tlast(e0_rx_axis_tlast),
    .rx_axis_tuser(e0_rx_axis_tuser),
    .rgmii_rx_clk(phy0_rx_clk), .rgmii_rxd(phy0_rxd), .rgmii_rx_ctl(phy0_rx_ctl),
    .rgmii_tx_clk(phy0_tx_clk), .rgmii_txd(phy0_txd), .rgmii_tx_ctl(phy0_tx_ctl),
    .tx_fifo_overflow(), .tx_fifo_bad_frame(), .tx_fifo_good_frame(),
    .rx_error_bad_frame(), .rx_error_bad_fcs(),
    .rx_fifo_overflow(), .rx_fifo_bad_frame(), .rx_fifo_good_frame(),
    .speed(), .cfg_ifg(8'd12), .cfg_tx_enable(1'b1), .cfg_rx_enable(1'b1)
);

eth_axis_rx eth_axis_rx_0 (
    .clk(clk), .rst(rst),
    .s_axis_tdata(e0_rx_axis_tdata), .s_axis_tvalid(e0_rx_axis_tvalid),
    .s_axis_tready(e0_rx_axis_tready), .s_axis_tlast(e0_rx_axis_tlast),
    .s_axis_tuser(e0_rx_axis_tuser),
    .m_eth_hdr_valid(e0_rx_eth_hdr_valid), .m_eth_hdr_ready(e0_rx_eth_hdr_ready),
    .m_eth_dest_mac(e0_rx_eth_dest_mac), .m_eth_src_mac(e0_rx_eth_src_mac),
    .m_eth_type(e0_rx_eth_type),
    .m_eth_payload_axis_tdata(e0_rx_eth_payload_tdata),
    .m_eth_payload_axis_tvalid(e0_rx_eth_payload_tvalid),
    .m_eth_payload_axis_tready(e0_rx_eth_payload_tready),
    .m_eth_payload_axis_tlast(e0_rx_eth_payload_tlast),
    .m_eth_payload_axis_tuser(e0_rx_eth_payload_tuser),
    .busy(), .error_header_early_termination()
);

eth_axis_tx eth_axis_tx_0 (
    .clk(clk), .rst(rst),
    .s_eth_hdr_valid(e0_tx_eth_hdr_valid), .s_eth_hdr_ready(e0_tx_eth_hdr_ready),
    .s_eth_dest_mac(e0_tx_eth_dest_mac), .s_eth_src_mac(e0_tx_eth_src_mac),
    .s_eth_type(e0_tx_eth_type),
    .s_eth_payload_axis_tdata(e0_tx_eth_payload_tdata),
    .s_eth_payload_axis_tvalid(e0_tx_eth_payload_tvalid),
    .s_eth_payload_axis_tready(e0_tx_eth_payload_tready),
    .s_eth_payload_axis_tlast(e0_tx_eth_payload_tlast),
    .s_eth_payload_axis_tuser(e0_tx_eth_payload_tuser),
    .m_axis_tdata(e0_tx_axis_tdata), .m_axis_tvalid(e0_tx_axis_tvalid),
    .m_axis_tready(e0_tx_axis_tready), .m_axis_tlast(e0_tx_axis_tlast),
    .m_axis_tuser(e0_tx_axis_tuser),
    .busy()
);

// ENET0 udp_complete — RX plaintext + TX decrypted + ARP
udp_complete udp_complete_0 (
    .clk(clk), .rst(rst),
    .s_eth_hdr_valid(e0_rx_eth_hdr_valid), .s_eth_hdr_ready(e0_rx_eth_hdr_ready),
    .s_eth_dest_mac(e0_rx_eth_dest_mac), .s_eth_src_mac(e0_rx_eth_src_mac),
    .s_eth_type(e0_rx_eth_type),
    .s_eth_payload_axis_tdata(e0_rx_eth_payload_tdata),
    .s_eth_payload_axis_tvalid(e0_rx_eth_payload_tvalid),
    .s_eth_payload_axis_tready(e0_rx_eth_payload_tready),
    .s_eth_payload_axis_tlast(e0_rx_eth_payload_tlast),
    .s_eth_payload_axis_tuser(e0_rx_eth_payload_tuser),
    .m_eth_hdr_valid(e0_tx_eth_hdr_valid), .m_eth_hdr_ready(e0_tx_eth_hdr_ready),
    .m_eth_dest_mac(e0_tx_eth_dest_mac), .m_eth_src_mac(e0_tx_eth_src_mac),
    .m_eth_type(e0_tx_eth_type),
    .m_eth_payload_axis_tdata(e0_tx_eth_payload_tdata),
    .m_eth_payload_axis_tvalid(e0_tx_eth_payload_tvalid),
    .m_eth_payload_axis_tready(e0_tx_eth_payload_tready),
    .m_eth_payload_axis_tlast(e0_tx_eth_payload_tlast),
    .m_eth_payload_axis_tuser(e0_tx_eth_payload_tuser),
    // IP — not used
    .s_ip_hdr_valid(1'b0), .s_ip_hdr_ready(), .s_ip_dscp(0), .s_ip_ecn(0),
    .s_ip_length(0), .s_ip_ttl(0), .s_ip_protocol(0),
    .s_ip_source_ip(0), .s_ip_dest_ip(0),
    .s_ip_payload_axis_tdata(0), .s_ip_payload_axis_tvalid(1'b0),
    .s_ip_payload_axis_tready(), .s_ip_payload_axis_tlast(0), .s_ip_payload_axis_tuser(0),
    .m_ip_hdr_valid(e0_rx_ip_hdr_valid), .m_ip_hdr_ready(e0_rx_ip_hdr_ready),
    .m_ip_eth_dest_mac(e0_rx_ip_eth_dest_mac), .m_ip_eth_src_mac(e0_rx_ip_eth_src_mac),
    .m_ip_eth_type(e0_rx_ip_eth_type),
    .m_ip_version(e0_rx_ip_version), .m_ip_ihl(e0_rx_ip_ihl),
    .m_ip_dscp(e0_rx_ip_dscp), .m_ip_ecn(e0_rx_ip_ecn),
    .m_ip_length(e0_rx_ip_length), .m_ip_identification(e0_rx_ip_identification),
    .m_ip_flags(e0_rx_ip_flags), .m_ip_fragment_offset(e0_rx_ip_fragment_offset),
    .m_ip_ttl(e0_rx_ip_ttl), .m_ip_protocol(e0_rx_ip_protocol),
    .m_ip_header_checksum(e0_rx_ip_header_checksum),
    .m_ip_source_ip(e0_rx_ip_source_ip), .m_ip_dest_ip(e0_rx_ip_dest_ip),
    .m_ip_payload_axis_tdata(e0_rx_ip_payload_tdata),
    .m_ip_payload_axis_tvalid(e0_rx_ip_payload_tvalid),
    .m_ip_payload_axis_tready(e0_rx_ip_payload_tready),
    .m_ip_payload_axis_tlast(e0_rx_ip_payload_tlast),
    .m_ip_payload_axis_tuser(e0_rx_ip_payload_tuser),
    // UDP TX — decrypted plaintext to PLC
    .s_udp_hdr_valid(e0_tx_udp_hdr_valid), .s_udp_hdr_ready(e0_tx_udp_hdr_ready),
    .s_udp_ip_dscp(e0_tx_udp_ip_dscp), .s_udp_ip_ecn(e0_tx_udp_ip_ecn),
    .s_udp_ip_ttl(e0_tx_udp_ip_ttl),
    .s_udp_ip_source_ip(e0_tx_udp_ip_source_ip), .s_udp_ip_dest_ip(e0_tx_udp_ip_dest_ip),
    .s_udp_source_port(e0_tx_udp_source_port), .s_udp_dest_port(e0_tx_udp_dest_port),
    .s_udp_length(e0_tx_udp_length), .s_udp_checksum(e0_tx_udp_checksum),
    .s_udp_payload_axis_tdata(e0_tx_udp_payload_tdata),
    .s_udp_payload_axis_tvalid(e0_tx_udp_payload_tvalid),
    .s_udp_payload_axis_tready(e0_tx_udp_payload_tready),
    .s_udp_payload_axis_tlast(e0_tx_udp_payload_tlast),
    .s_udp_payload_axis_tuser(e0_tx_udp_payload_tuser),
    // UDP RX — plaintext from PLC
    .m_udp_hdr_valid(e0_rx_udp_hdr_valid), .m_udp_hdr_ready(e0_rx_udp_hdr_ready),
    .m_udp_eth_dest_mac(e0_rx_udp_eth_dest_mac), .m_udp_eth_src_mac(e0_rx_udp_eth_src_mac),
    .m_udp_eth_type(e0_rx_udp_eth_type),
    .m_udp_ip_version(e0_rx_udp_ip_version), .m_udp_ip_ihl(e0_rx_udp_ip_ihl),
    .m_udp_ip_dscp(e0_rx_udp_ip_dscp), .m_udp_ip_ecn(e0_rx_udp_ip_ecn),
    .m_udp_ip_length(e0_rx_udp_ip_length), .m_udp_ip_identification(e0_rx_udp_ip_identification),
    .m_udp_ip_flags(e0_rx_udp_ip_flags), .m_udp_ip_fragment_offset(e0_rx_udp_ip_fragment_offset),
    .m_udp_ip_ttl(e0_rx_udp_ip_ttl), .m_udp_ip_protocol(e0_rx_udp_ip_protocol),
    .m_udp_ip_header_checksum(e0_rx_udp_ip_header_checksum),
    .m_udp_ip_source_ip(e0_rx_udp_ip_source_ip), .m_udp_ip_dest_ip(e0_rx_udp_ip_dest_ip),
    .m_udp_source_port(e0_rx_udp_source_port), .m_udp_dest_port(e0_rx_udp_dest_port),
    .m_udp_length(e0_rx_udp_length), .m_udp_checksum(e0_rx_udp_checksum),
    .m_udp_payload_axis_tdata(e0_rx_udp_payload_tdata),
    .m_udp_payload_axis_tvalid(e0_rx_udp_payload_tvalid),
    .m_udp_payload_axis_tready(e0_rx_udp_payload_tready),
    .m_udp_payload_axis_tlast(e0_rx_udp_payload_tlast),
    .m_udp_payload_axis_tuser(e0_rx_udp_payload_tuser),
    // Status
    .ip_rx_busy(), .ip_tx_busy(), .udp_rx_busy(), .udp_tx_busy(),
    .ip_rx_error_header_early_termination(), .ip_rx_error_payload_early_termination(),
    .ip_rx_error_invalid_header(), .ip_rx_error_invalid_checksum(),
    .ip_tx_error_payload_early_termination(), .ip_tx_error_arp_failed(),
    .udp_rx_error_header_early_termination(), .udp_rx_error_payload_early_termination(),
    .udp_tx_error_payload_early_termination(),
    .local_mac(LOCAL_MAC_0), .local_ip(LOCAL_IP_0),
    .gateway_ip(GATEWAY_IP_0), .subnet_mask(SUBNET_MASK_0),
    .clear_arp_cache(0)
);

// ================================================================
// ENET1: Ethernet MAC (Network side — encrypted)
// ================================================================
eth_mac_1g_rgmii_fifo #(
    .TARGET(TARGET), .USE_CLK90("TRUE"), .ENABLE_PADDING(1),
    .MIN_FRAME_LENGTH(64), .TX_FIFO_DEPTH(2048), .TX_FRAME_FIFO(1),
    .RX_FIFO_DEPTH(2048), .RX_FRAME_FIFO(1)
)
eth_mac_1 (
    .gtx_clk(clk), .gtx_clk90(clk90), .gtx_rst(rst),
    .logic_clk(clk), .logic_rst(rst),
    .tx_axis_tdata(e1_tx_axis_tdata), .tx_axis_tvalid(e1_tx_axis_tvalid),
    .tx_axis_tready(e1_tx_axis_tready), .tx_axis_tlast(e1_tx_axis_tlast),
    .tx_axis_tuser(e1_tx_axis_tuser),
    .rx_axis_tdata(e1_rx_axis_tdata), .rx_axis_tvalid(e1_rx_axis_tvalid),
    .rx_axis_tready(e1_rx_axis_tready), .rx_axis_tlast(e1_rx_axis_tlast),
    .rx_axis_tuser(e1_rx_axis_tuser),
    .rgmii_rx_clk(phy1_rx_clk), .rgmii_rxd(phy1_rxd), .rgmii_rx_ctl(phy1_rx_ctl),
    .rgmii_tx_clk(phy1_tx_clk), .rgmii_txd(phy1_txd), .rgmii_tx_ctl(phy1_tx_ctl),
    .tx_fifo_overflow(), .tx_fifo_bad_frame(), .tx_fifo_good_frame(),
    .rx_error_bad_frame(), .rx_error_bad_fcs(),
    .rx_fifo_overflow(), .rx_fifo_bad_frame(), .rx_fifo_good_frame(),
    .speed(), .cfg_ifg(8'd12), .cfg_tx_enable(1'b1), .cfg_rx_enable(1'b1)
);

eth_axis_rx eth_axis_rx_1 (
    .clk(clk), .rst(rst),
    .s_axis_tdata(e1_rx_axis_tdata), .s_axis_tvalid(e1_rx_axis_tvalid),
    .s_axis_tready(e1_rx_axis_tready), .s_axis_tlast(e1_rx_axis_tlast),
    .s_axis_tuser(e1_rx_axis_tuser),
    .m_eth_hdr_valid(e1_rx_eth_hdr_valid), .m_eth_hdr_ready(e1_rx_eth_hdr_ready),
    .m_eth_dest_mac(e1_rx_eth_dest_mac), .m_eth_src_mac(e1_rx_eth_src_mac),
    .m_eth_type(e1_rx_eth_type),
    .m_eth_payload_axis_tdata(e1_rx_eth_payload_tdata),
    .m_eth_payload_axis_tvalid(e1_rx_eth_payload_tvalid),
    .m_eth_payload_axis_tready(e1_rx_eth_payload_tready),
    .m_eth_payload_axis_tlast(e1_rx_eth_payload_tlast),
    .m_eth_payload_axis_tuser(e1_rx_eth_payload_tuser),
    .busy(), .error_header_early_termination()
);

eth_axis_tx eth_axis_tx_1 (
    .clk(clk), .rst(rst),
    .s_eth_hdr_valid(e1_tx_eth_hdr_valid), .s_eth_hdr_ready(e1_tx_eth_hdr_ready),
    .s_eth_dest_mac(e1_tx_eth_dest_mac), .s_eth_src_mac(e1_tx_eth_src_mac),
    .s_eth_type(e1_tx_eth_type),
    .s_eth_payload_axis_tdata(e1_tx_eth_payload_tdata),
    .s_eth_payload_axis_tvalid(e1_tx_eth_payload_tvalid),
    .s_eth_payload_axis_tready(e1_tx_eth_payload_tready),
    .s_eth_payload_axis_tlast(e1_tx_eth_payload_tlast),
    .s_eth_payload_axis_tuser(e1_tx_eth_payload_tuser),
    .m_axis_tdata(e1_tx_axis_tdata), .m_axis_tvalid(e1_tx_axis_tvalid),
    .m_axis_tready(e1_tx_axis_tready), .m_axis_tlast(e1_tx_axis_tlast),
    .m_axis_tuser(e1_tx_axis_tuser),
    .busy()
);

// ENET1 udp_complete — TX encrypted + RX encrypted (for decrypt) + ARP
udp_complete udp_complete_1 (
    .clk(clk), .rst(rst),
    .s_eth_hdr_valid(e1_rx_eth_hdr_valid), .s_eth_hdr_ready(e1_rx_eth_hdr_ready),
    .s_eth_dest_mac(e1_rx_eth_dest_mac), .s_eth_src_mac(e1_rx_eth_src_mac),
    .s_eth_type(e1_rx_eth_type),
    .s_eth_payload_axis_tdata(e1_rx_eth_payload_tdata),
    .s_eth_payload_axis_tvalid(e1_rx_eth_payload_tvalid),
    .s_eth_payload_axis_tready(e1_rx_eth_payload_tready),
    .s_eth_payload_axis_tlast(e1_rx_eth_payload_tlast),
    .s_eth_payload_axis_tuser(e1_rx_eth_payload_tuser),
    .m_eth_hdr_valid(e1_tx_eth_hdr_valid), .m_eth_hdr_ready(e1_tx_eth_hdr_ready),
    .m_eth_dest_mac(e1_tx_eth_dest_mac), .m_eth_src_mac(e1_tx_eth_src_mac),
    .m_eth_type(e1_tx_eth_type),
    .m_eth_payload_axis_tdata(e1_tx_eth_payload_tdata),
    .m_eth_payload_axis_tvalid(e1_tx_eth_payload_tvalid),
    .m_eth_payload_axis_tready(e1_tx_eth_payload_tready),
    .m_eth_payload_axis_tlast(e1_tx_eth_payload_tlast),
    .m_eth_payload_axis_tuser(e1_tx_eth_payload_tuser),
    // IP — not used
    .s_ip_hdr_valid(1'b0), .s_ip_hdr_ready(), .s_ip_dscp(0), .s_ip_ecn(0),
    .s_ip_length(0), .s_ip_ttl(0), .s_ip_protocol(0),
    .s_ip_source_ip(0), .s_ip_dest_ip(0),
    .s_ip_payload_axis_tdata(0), .s_ip_payload_axis_tvalid(1'b0),
    .s_ip_payload_axis_tready(), .s_ip_payload_axis_tlast(0), .s_ip_payload_axis_tuser(0),
    .m_ip_hdr_valid(e1_rx_ip_hdr_valid), .m_ip_hdr_ready(e1_rx_ip_hdr_ready),
    .m_ip_eth_dest_mac(e1_rx_ip_eth_dest_mac), .m_ip_eth_src_mac(e1_rx_ip_eth_src_mac),
    .m_ip_eth_type(e1_rx_ip_eth_type),
    .m_ip_version(e1_rx_ip_version), .m_ip_ihl(e1_rx_ip_ihl),
    .m_ip_dscp(e1_rx_ip_dscp), .m_ip_ecn(e1_rx_ip_ecn),
    .m_ip_length(e1_rx_ip_length), .m_ip_identification(e1_rx_ip_identification),
    .m_ip_flags(e1_rx_ip_flags), .m_ip_fragment_offset(e1_rx_ip_fragment_offset),
    .m_ip_ttl(e1_rx_ip_ttl), .m_ip_protocol(e1_rx_ip_protocol),
    .m_ip_header_checksum(e1_rx_ip_header_checksum),
    .m_ip_source_ip(e1_rx_ip_source_ip), .m_ip_dest_ip(e1_rx_ip_dest_ip),
    .m_ip_payload_axis_tdata(e1_rx_ip_payload_tdata),
    .m_ip_payload_axis_tvalid(e1_rx_ip_payload_tvalid),
    .m_ip_payload_axis_tready(e1_rx_ip_payload_tready),
    .m_ip_payload_axis_tlast(e1_rx_ip_payload_tlast),
    .m_ip_payload_axis_tuser(e1_rx_ip_payload_tuser),
    // UDP TX — encrypted payload to FPGA2
    .s_udp_hdr_valid(e1_tx_udp_hdr_valid), .s_udp_hdr_ready(e1_tx_udp_hdr_ready),
    .s_udp_ip_dscp(e1_tx_udp_ip_dscp), .s_udp_ip_ecn(e1_tx_udp_ip_ecn),
    .s_udp_ip_ttl(e1_tx_udp_ip_ttl),
    .s_udp_ip_source_ip(e1_tx_udp_ip_source_ip), .s_udp_ip_dest_ip(e1_tx_udp_ip_dest_ip),
    .s_udp_source_port(e1_tx_udp_source_port), .s_udp_dest_port(e1_tx_udp_dest_port),
    .s_udp_length(e1_tx_udp_length), .s_udp_checksum(e1_tx_udp_checksum),
    .s_udp_payload_axis_tdata(e1_tx_udp_payload_tdata),
    .s_udp_payload_axis_tvalid(e1_tx_udp_payload_tvalid),
    .s_udp_payload_axis_tready(e1_tx_udp_payload_tready),
    .s_udp_payload_axis_tlast(e1_tx_udp_payload_tlast),
    .s_udp_payload_axis_tuser(e1_tx_udp_payload_tuser),
    // UDP RX — encrypted from network (for decrypt)
    .m_udp_hdr_valid(e1_rx_udp_hdr_valid), .m_udp_hdr_ready(e1_rx_udp_hdr_ready),
    .m_udp_eth_dest_mac(e1_rx_udp_eth_dest_mac), .m_udp_eth_src_mac(e1_rx_udp_eth_src_mac),
    .m_udp_eth_type(e1_rx_udp_eth_type),
    .m_udp_ip_version(e1_rx_udp_ip_version), .m_udp_ip_ihl(e1_rx_udp_ip_ihl),
    .m_udp_ip_dscp(e1_rx_udp_ip_dscp), .m_udp_ip_ecn(e1_rx_udp_ip_ecn),
    .m_udp_ip_length(e1_rx_udp_ip_length), .m_udp_ip_identification(e1_rx_udp_ip_identification),
    .m_udp_ip_flags(e1_rx_udp_ip_flags), .m_udp_ip_fragment_offset(e1_rx_udp_ip_fragment_offset),
    .m_udp_ip_ttl(e1_rx_udp_ip_ttl), .m_udp_ip_protocol(e1_rx_udp_ip_protocol),
    .m_udp_ip_header_checksum(e1_rx_udp_ip_header_checksum),
    .m_udp_ip_source_ip(e1_rx_udp_ip_source_ip), .m_udp_ip_dest_ip(e1_rx_udp_ip_dest_ip),
    .m_udp_source_port(e1_rx_udp_source_port), .m_udp_dest_port(e1_rx_udp_dest_port),
    .m_udp_length(e1_rx_udp_length), .m_udp_checksum(e1_rx_udp_checksum),
    .m_udp_payload_axis_tdata(e1_rx_udp_payload_tdata),
    .m_udp_payload_axis_tvalid(e1_rx_udp_payload_tvalid),
    .m_udp_payload_axis_tready(e1_rx_udp_payload_tready),
    .m_udp_payload_axis_tlast(e1_rx_udp_payload_tlast),
    .m_udp_payload_axis_tuser(e1_rx_udp_payload_tuser),
    // Status
    .ip_rx_busy(), .ip_tx_busy(), .udp_rx_busy(), .udp_tx_busy(),
    .ip_rx_error_header_early_termination(), .ip_rx_error_payload_early_termination(),
    .ip_rx_error_invalid_header(), .ip_rx_error_invalid_checksum(),
    .ip_tx_error_payload_early_termination(), .ip_tx_error_arp_failed(),
    .udp_rx_error_header_early_termination(), .udp_rx_error_payload_early_termination(),
    .udp_tx_error_payload_early_termination(),
    .local_mac(LOCAL_MAC_1), .local_ip(LOCAL_IP_1),
    .gateway_ip(GATEWAY_IP_1), .subnet_mask(SUBNET_MASK_1),
    .clear_arp_cache(0)
);

// ================================================================
// ENCRYPT PATH: Async FIFO 125→62.5MHz (ENET0 RX → ASCON encrypt)
// ================================================================
axis_async_fifo #(
    .DEPTH(2048), .DATA_WIDTH(8), .KEEP_ENABLE(0), .LAST_ENABLE(1),
    .ID_ENABLE(0), .DEST_ENABLE(0), .USER_ENABLE(0), .FRAME_FIFO(0)
)
enc_rx_fifo (
    .s_clk(clk), .s_rst(rst),
    .s_axis_tdata(enc_rx_filt_tdata), .s_axis_tkeep(0),
    .s_axis_tvalid(enc_rx_filt_tvalid), .s_axis_tready(enc_rx_filt_tready),
    .s_axis_tlast(enc_rx_filt_tlast),
    .s_axis_tid(0), .s_axis_tdest(0), .s_axis_tuser(0),
    .m_clk(clk_slow), .m_rst(rst_slow),
    .m_axis_tdata(enc_slow_rx_tdata), .m_axis_tkeep(),
    .m_axis_tvalid(enc_slow_rx_tvalid), .m_axis_tready(enc_slow_rx_tready),
    .m_axis_tlast(enc_slow_rx_tlast),
    .m_axis_tid(), .m_axis_tdest(), .m_axis_tuser(),
    .s_status_overflow(), .s_status_bad_frame(), .s_status_good_frame(),
    .m_status_overflow(), .m_status_bad_frame(), .m_status_good_frame()
);

// ================================================================
// ASCON Encryption Wrapper (62.5MHz domain)
// ================================================================
ascon_udp_wrapper ascon_enc_inst (
    .clk(clk_slow), .rst_n(~rst_slow),
    .s_axis_tdata(enc_slow_rx_tdata), .s_axis_tvalid(enc_slow_rx_tvalid),
    .s_axis_tready(enc_slow_rx_tready), .s_axis_tlast(enc_slow_rx_tlast),
    .m_axis_tdata(enc_slow_tx_tdata), .m_axis_tvalid(enc_slow_tx_tvalid),
    .m_axis_tready(enc_slow_tx_tready), .m_axis_tlast(enc_slow_tx_tlast)
);

// ================================================================
// ENCRYPT PATH: Async FIFO 62.5→125MHz (ASCON encrypt → ENET1 TX)
// ================================================================
axis_async_fifo #(
    .DEPTH(2048), .DATA_WIDTH(8), .KEEP_ENABLE(0), .LAST_ENABLE(1),
    .ID_ENABLE(0), .DEST_ENABLE(0), .USER_ENABLE(0), .FRAME_FIFO(0)
)
enc_tx_fifo (
    .s_clk(clk_slow), .s_rst(rst_slow),
    .s_axis_tdata(enc_slow_tx_tdata), .s_axis_tkeep(0),
    .s_axis_tvalid(enc_slow_tx_tvalid), .s_axis_tready(enc_slow_tx_tready),
    .s_axis_tlast(enc_slow_tx_tlast),
    .s_axis_tid(0), .s_axis_tdest(0), .s_axis_tuser(0),
    .m_clk(clk), .m_rst(rst),
    .m_axis_tdata(enc_out_tdata), .m_axis_tkeep(),
    .m_axis_tvalid(enc_out_tvalid), .m_axis_tready(enc_out_tready),
    .m_axis_tlast(enc_out_tlast),
    .m_axis_tid(), .m_axis_tdest(), .m_axis_tuser(),
    .s_status_overflow(), .s_status_bad_frame(), .s_status_good_frame(),
    .m_status_overflow(), .m_status_bad_frame(), .m_status_good_frame()
);

// ================================================================
// DECRYPT PATH: Async FIFO 125→62.5MHz (ENET1 RX → ASCON decrypt)
// ================================================================
axis_async_fifo #(
    .DEPTH(2048), .DATA_WIDTH(8), .KEEP_ENABLE(0), .LAST_ENABLE(1),
    .ID_ENABLE(0), .DEST_ENABLE(0), .USER_ENABLE(0), .FRAME_FIFO(0)
)
dec_rx_fifo (
    .s_clk(clk), .s_rst(rst),
    .s_axis_tdata(dec_rx_filt_tdata), .s_axis_tkeep(0),
    .s_axis_tvalid(dec_rx_filt_tvalid), .s_axis_tready(dec_rx_filt_tready),
    .s_axis_tlast(dec_rx_filt_tlast),
    .s_axis_tid(0), .s_axis_tdest(0), .s_axis_tuser(0),
    .m_clk(clk_slow), .m_rst(rst_slow),
    .m_axis_tdata(dec_slow_rx_tdata), .m_axis_tkeep(),
    .m_axis_tvalid(dec_slow_rx_tvalid), .m_axis_tready(dec_slow_rx_tready),
    .m_axis_tlast(dec_slow_rx_tlast),
    .m_axis_tid(), .m_axis_tdest(), .m_axis_tuser(),
    .s_status_overflow(), .s_status_bad_frame(), .s_status_good_frame(),
    .m_status_overflow(), .m_status_bad_frame(), .m_status_good_frame()
);

// ================================================================
// ASCON Decryption Wrapper (62.5MHz domain)
// ================================================================
ascon_udp_decrypt ascon_dec_inst (
    .clk(clk_slow), .rst_n(~rst_slow),
    .s_axis_tdata(dec_slow_rx_tdata), .s_axis_tvalid(dec_slow_rx_tvalid),
    .s_axis_tready(dec_slow_rx_tready), .s_axis_tlast(dec_slow_rx_tlast),
    .m_axis_tdata(dec_slow_tx_tdata), .m_axis_tvalid(dec_slow_tx_tvalid),
    .m_axis_tready(dec_slow_tx_tready), .m_axis_tlast(dec_slow_tx_tlast)
);

// ================================================================
// DECRYPT PATH: Async FIFO 62.5→125MHz (ASCON decrypt → ENET0 TX)
// ================================================================
axis_async_fifo #(
    .DEPTH(2048), .DATA_WIDTH(8), .KEEP_ENABLE(0), .LAST_ENABLE(1),
    .ID_ENABLE(0), .DEST_ENABLE(0), .USER_ENABLE(0), .FRAME_FIFO(0)
)
dec_tx_fifo (
    .s_clk(clk_slow), .s_rst(rst_slow),
    .s_axis_tdata(dec_slow_tx_tdata), .s_axis_tkeep(0),
    .s_axis_tvalid(dec_slow_tx_tvalid), .s_axis_tready(dec_slow_tx_tready),
    .s_axis_tlast(dec_slow_tx_tlast),
    .s_axis_tid(0), .s_axis_tdest(0), .s_axis_tuser(0),
    .m_clk(clk), .m_rst(rst),
    .m_axis_tdata(dec_out_tdata), .m_axis_tkeep(),
    .m_axis_tvalid(dec_out_tvalid), .m_axis_tready(dec_out_tready),
    .m_axis_tlast(dec_out_tlast),
    .m_axis_tid(), .m_axis_tdest(), .m_axis_tuser(),
    .s_status_overflow(), .s_status_bad_frame(), .s_status_good_frame(),
    .m_status_overflow(), .m_status_bad_frame(), .m_status_good_frame()
);

endmodule

`resetall