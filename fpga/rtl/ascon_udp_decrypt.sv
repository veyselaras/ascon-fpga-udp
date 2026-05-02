// =============================================================================
// Project:      ASCON Authenticated Decryption for UDP/IP
// Module:       ascon_udp_decrypt
// Description:  ASCON UDP Decryption Wrapper This module acts as a bridge between an 
// 				  incoming AXI-Stream (from Ethernet RX) and the ASCON LWC (Lightweight Cryptography) core. 
// 
// Step-by-Step Operation:
// 1. Buffers incoming 8-bit AXI-Stream UDP payload into 32-bit words in a FIFO RAM.
// 2. Simultaneously extracts the last 16 bytes on-the-fly to isolate the authentication tag.
// 3. Feeds the ASCON core with the Mode, Key, Nonce, Associated Data (AD), and Ciphertext.
// 4. Captures the decrypted output into a secondary RAM.
// 5. Validates the authentication tag. If valid, streams the decrypted data out via AXI-Stream.
// If invalid, drops the packet entirely.
// 
// Developer:    Veysel Aras
// =============================================================================

`timescale 1ns / 1ps
`include "ascon-verilog/rtl/config.sv"

module ascon_udp_decrypt (
    input logic clk,
    input logic rst_n,

    // -------------------------------------------------------------------------
    // AXI Stream Input (FIFO - 8 bit) - Encrypted data from Network (ENET1)
    // -------------------------------------------------------------------------
    input  logic [7:0] s_axis_tdata,
    input  logic       s_axis_tvalid,
    output logic       s_axis_tready,
    input  logic       s_axis_tlast,

    // -------------------------------------------------------------------------
    // AXI Stream Output (TX - 8 bit) - Decrypted plaintext to PC (ENET0)
    // -------------------------------------------------------------------------
    output logic [7:0] m_axis_tdata,
    output logic       m_axis_tvalid,
    input  logic       m_axis_tready,
    output logic       m_axis_tlast
);

  // -------------------------------------------------------------------------
  // Internal Signals (ASCON LWC Interface)
  // -------------------------------------------------------------------------
  logic        key_valid;
  logic [31:0] key;
  logic        key_ready;

  logic [31:0] bdi;         // Block Data Input
  logic [ 3:0] bdi_valid;   // Byte valid mask
  logic        bdi_ready;
  logic [ 3:0] bdi_type;    // Data type (Nonce, AD, Msg, Tag)
  logic        bdi_eot;     // End of Type
  logic        bdi_eoi;     // End of Input

  logic [ 3:0] mode;        // 2 = Decryption

  logic [31:0] bdo;         // Block Data Output (Decrypted Plaintext)
  logic        bdo_valid;
  logic [ 3:0] bdo_type;
  logic        bdo_eot;
  logic        bdo_eoo;
  logic        bdo_ready;

  logic        auth;        // Authentication success flag
  logic        auth_valid;  // Authentication computation done

  // -------------------------------------------------------------------------
  // Ascon LWC Core Instantiation
  // -------------------------------------------------------------------------
  ascon_core u_ascon (
      .clk       (clk),
      .rst       (~rst_n),
      .key       (key),
      .key_valid (key_valid),
      .key_ready (key_ready),
      .bdi       (bdi),
      .bdi_valid (bdi_valid),
      .bdi_ready (bdi_ready),
      .bdi_type  (data_t'(bdi_type)),
      .bdi_eot   (bdi_eot),
      .bdi_eoi   (bdi_eoi),
      .mode      (mode_t'(mode)),
      .bdo       (bdo),
      .bdo_valid (bdo_valid),
      .bdo_ready (bdo_ready),
      .bdo_type  (bdo_type),
      .bdo_eot   (bdo_eot),
      .bdo_eoo   (bdo_eoo),
      .auth      (auth),
      .auth_valid(auth_valid)
  );

  // Fixed keys for current testing phase
  localparam logic [127:0] FIXED_AD = 128'h000000000000000000000000DDEEFF00;
  localparam logic [127:0] FIXED_KEY = 128'h000102030405060708090A0B0C0D0E0F;

  // FSM State Definitions
  typedef enum logic [3:0] {
    S_IDLE              = 4'd0, // Wait for incoming AXI packet
    S_PACK_UDP_PAYLOAD = 4'd1, // Buffer UDP packet, extract tag
    S_SEND_MODE         = 4'd2, // Initialize ASCON mode
    S_SEND_KEY          = 4'd3, // Stream 128-bit key
    S_SEND_NONCE        = 4'd4, // Stream Nonce from buffered data
    S_SEND_AD           = 4'd5, // Stream Associated Data
    S_SEND_CIPHERTEXT   = 4'd6, // Stream Ciphertext, capture decrypted output
    S_SEND_TAG          = 4'd7, // Send isolated 16-byte tag for verification
    S_SEND2TX           = 4'd8  // If authenticated, transmit plaintext
  } state_t;


  state_t         state;

  // Counters for tracking memory addresses and data alignment
  logic   [ 10:0] rx_fifo_wr_addr;
  logic   [ 10:0] rx_fifo_rd_addr;
  logic   [  1:0] key_word_cnt;
  logic   [  1:0] nonce_word_cnt;

  logic   [ 10:0] decrypted_data_cnt;
  logic   [  1:0] decrypted_algn_cnt;

  logic   [ 10:0] tx_word_addr;
  logic   [ 10:0] ct_word_len;


  // Registers for capturing LWC output safely
  logic   [ 31:0] bdo_captured;
  logic           bdo_capture_valid;
  logic   [  3:0] bdi_valid_captured;
  logic           bdo_send;

  // Data packing buffers
  logic   [ 31:0] rx_pack_buf;
  logic   [  1:0] rx_byte_idx;    // Tracks 8-bit to 32-bit packing

  logic   [  1:0] tx_unpack_idx;
  logic   [ 10:0] dec_total_bytes;
  logic   [ 10:0] dec_sent_bytes;

  logic   [127:0] tag_buf;              // Sliding window to isolate the 16-byte MAC tag
  logic   [ 10:0] total_byte_cnt;       // Total incoming bytes count

  logic   [  1:0] tag_word_cnt;

  logic   [ 31:0] tag_raw;

  // --- fifo_data RAM signals (Stores incoming encrypted UDP payload) ---
  logic           fifo_wr_en;
  logic   [  8:0] fifo_wr_addr;
  logic   [ 31:0] fifo_wr_data;
  logic   [  8:0] fifo_rd_addr;
  logic   [ 31:0] fifo_rd_data;

  // --- decrypted_data RAM signals (Stores ASCON plaintext output) ---
  logic           dec_wr_en;
  logic   [  8:0] dec_wr_addr;
  logic   [ 31:0] dec_wr_data;
  logic   [  8:0] dec_rd_addr;
  logic   [ 31:0] dec_rd_data;

  // --- RAM instances ---
  // Using True Dual Port RAMs allows simultaneous read/write if needed, 
  // and keeps memory inference clean for Quartus synthesis.
  true_dual_port_ram_single_clock #(
      .DATA_WIDTH(32),
      .ADDR_WIDTH(9)
  ) fifo_ram (
      .clk(clk),
      .we_a(fifo_wr_en),
      .addr_a(fifo_wr_addr),
      .data_a(fifo_wr_data),
      .q_a(),
      .we_b(1'b0),
      .addr_b(fifo_rd_addr),
      .data_b(32'd0),
      .q_b(fifo_rd_data)
  );

  true_dual_port_ram_single_clock #(
      .DATA_WIDTH(32),
      .ADDR_WIDTH(9)
  ) dec_ram (
      .clk(clk),
      .we_a(dec_wr_en),
      .addr_a(dec_wr_addr),
      .data_a(dec_wr_data),
      .q_a(),
      .we_b(1'b0),
      .addr_b(dec_rd_addr),
      .data_b(32'd0),
      .q_b(dec_rd_data)
  );

  logic [8:0] fifo_rd_addr_reg;
  // Address mux: If reading Ciphertext (type 3), use auto-incremented word count, else use manual register
  assign fifo_rd_addr = bdo_type == 4'd3 ? rx_fifo_rd_addr[8:0] + 9'd1 : fifo_rd_addr_reg;


  // =========================================================================
  // Combinational Logic block - Drives ASCON inputs based on current FSM state
  // =========================================================================
  always_comb begin
    // ----- Defaults (latch prevention) -----
    s_axis_tready = 1'b1;
    key_valid     = 1'b0;
    key           = 32'h0;
    mode          = 4'h0;
    bdi           = 32'h0;
    bdi_valid     = 4'h0;
    bdi_type      = 4'h0;
    bdi_eot       = 1'b0;
    bdi_eoi       = 1'b0;
    bdo_ready     = 1'b0;
    m_axis_tvalid = 1'b0;
    m_axis_tdata  = 8'd0;
    m_axis_tlast  = 1'b0;
    tag_raw       = 32'h0;
    unique case (state)
      S_IDLE: begin
        s_axis_tready = 1'b1; // Always ready to receive new packet
      end

      // ---------------------------------------------------------
      S_PACK_UDP_PAYLOAD: begin
        s_axis_tready = 1'b1;
      end

      // ---------------------------------------------------------
      // mode=2 (Decrypt) and key_valid=1 must assert on the same cycle.
      // The ASCON core checks both simultaneously when leaving idle.
      // ---------------------------------------------------------
      S_SEND_MODE: begin
        mode      = 4'h2;
        key_valid = 1'b1;
        key       = FIXED_KEY[(key_word_cnt*32)+:32];
      end

      // ---------------------------------------------------------
      S_SEND_KEY: begin
        key_valid = 1'b1;
        key       = FIXED_KEY[(key_word_cnt*32)+:32];
      end

      // ---------------------------------------------------------
      S_SEND_NONCE: begin
        bdi_type = 4'h1;  // LWC Type: D_NONCE
        bdi_valid = 4'hF;
        bdi = fifo_rd_data;
        // Assert End-of-Type on the last nonce word
        if (nonce_word_cnt == 2'd0) bdi_eot = 1'b1;
      end

      // ---------------------------------------------------------
      S_SEND_AD: begin
        bdi_type = 4'h2;  // LWC Type: D_AD
        bdi_valid = 4'hF;
        bdi = fifo_rd_data;
        bdi_eot = 1'b1;
        bdi_eoi = 1'b0;

        // If this is the last piece of data before ciphertext
        if (rx_fifo_wr_addr <= 1) begin
          bdi_eoi = 1'b1;
          bdi_eot = 1'b1;
          bdi = fifo_rd_data;
        end
      end

      // ---------------------------------------------------------
      S_SEND_CIPHERTEXT: begin
        bdo_ready = 1'b1;   // Ready to receive decrypted plaintext
        bdi_type  = 4'h3;   // LWC Type: D_MSG (Ciphertext in decrypt mode)
        bdi_valid = 4'hF;
        bdi_eoi   = 1'b0;
        bdi_eot   = 1'b0;

        // Handle partial words at the end of the ciphertext stream
        if (rx_fifo_wr_addr <= 1) begin
          bdi_eoi = 1'b1;
          bdi_eot = 1'b1;
          bdi = fifo_rd_data;

          // Calculate byte-valid mask for unaligned packet endings
          if (rx_byte_idx != 2'd0) begin
            bdi_valid = 4'((5'b00001 << rx_byte_idx) - 1'b1);
          end
        end else begin
          bdi = fifo_rd_data;
        end

      end

      // ---------------------------------------------------------
      S_SEND_TAG: begin
        bdi_type  = 4'h4;  // LWC Type: D_TAG
        bdi_valid = 4'hF;

        // Multiplex the 128-bit tag captured during S_PACK_UDP_PAYLOAD
        unique case (tag_word_cnt)
          2'd0: tag_raw = tag_buf[127:96];
          2'd1: tag_raw = tag_buf[95:64];
          2'd2: tag_raw = tag_buf[63:32];
          2'd3: tag_raw = tag_buf[31:0];
        endcase

        // Byte swap: The LWC core expects little-endian, but network is big-endian
        bdi = {tag_raw[7:0], tag_raw[15:8], tag_raw[23:16], tag_raw[31:24]};

        if (tag_word_cnt == 2'd3) bdi_eot = 1'b1;

      end

      // ---------------------------------------------------------
      S_SEND2TX: begin
        // SECURITY CRITICAL: Only assert m_axis_tvalid if Authentication passed!
        // If 'auth' is low, the packet was tampered with and is discarded silently.
        if (auth_valid && auth) begin
          m_axis_tvalid = 1'b1;

          // Unpack 32-bit RAM data back into 8-bit AXI Stream
          unique case (tx_unpack_idx)
            2'd0: m_axis_tdata = rx_pack_buf[7:0];
            2'd1: m_axis_tdata = rx_pack_buf[15:8];
            2'd2: m_axis_tdata = rx_pack_buf[23:16];
            2'd3: m_axis_tdata = rx_pack_buf[31:24];
          endcase

          // Assert tlast on the final byte
          if (dec_sent_bytes == dec_total_bytes - 11'd1) m_axis_tlast = 1'b1;
        end

      end
    endcase
  end

  // =========================================================================
  // Sequential Logic block - FSM transitions and RAM control
  // =========================================================================
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      // Reset all pointers, counters, and state
      fifo_wr_en         <= 1'b0;
      fifo_wr_addr       <= 9'd0;
      fifo_wr_data       <= 32'd0;
      fifo_rd_addr_reg   <= 9'd0;
      dec_wr_en          <= 1'b0;
      dec_wr_addr        <= 9'd0;
      dec_wr_data        <= 32'd0;
      dec_rd_addr        <= 9'd0;
      tag_word_cnt       <= 2'd0;
      tag_buf            <= 128'd0;
      total_byte_cnt     <= 11'd0;
      bdo_send           <= 1'b1;
      bdi_valid_captured <= 4'd0;
      state              <= S_IDLE;
      rx_fifo_wr_addr      <= 11'd0;
      rx_fifo_rd_addr      <= 11'd0;
      key_word_cnt       <= 2'd0;
      nonce_word_cnt     <= 2'd0;
      decrypted_data_cnt <= 11'd0;
      decrypted_algn_cnt <= 2'd0;
      tx_word_addr      <= 11'd0;
      ct_word_len             <= 11'd0;
      bdo_captured       <= 32'd0;
      bdo_capture_valid  <= 1'b0;
      rx_pack_buf        <= 32'd0;
      rx_byte_idx  <= 2'd0;
      tx_unpack_idx       <= 2'd0;
      dec_total_bytes    <= 11'd0;
      dec_sent_bytes     <= 11'd0;
    end else begin
      // Default to no memory write unless explicitly requested
      fifo_wr_en <= 1'b0;
      dec_wr_en  <= 1'b0;
      case (state)
        // ---------------------------------------------------------
        S_IDLE: begin

          bdi_valid_captured <= 4'd0;
          if (s_axis_tvalid) begin
            // Start capturing first byte of new packet
            rx_pack_buf[7:0]  <= s_axis_tdata;
            rx_byte_idx <= 2'd1;
            state             <= S_PACK_UDP_PAYLOAD;
            // Catch edge case where packet is only 1 byte
            if (s_axis_tlast) begin
              state <= S_SEND_MODE;
            end
          end
        end

        // ---------------------------------------------------------
        //sikinti
        S_PACK_UDP_PAYLOAD: begin
          // Shift register sliding window to catch the 16-byte MAC Tag.
          // Because AXI Stream doesn't tell us ahead of time where the payload ends,
          // we keep the last 16 bytes in this buffer. When tlast hits, tag_buf holds the tag.
          if (s_axis_tvalid) begin
            tag_buf <= {tag_buf[119:0], s_axis_tdata};
            total_byte_cnt <= total_byte_cnt + 11'd1;

            // Pack 8-bit AXI data into 32-bit register
            rx_pack_buf[rx_byte_idx*8+:8] <= s_axis_tdata;
            rx_byte_idx <= rx_byte_idx + 2'd1;

            // When rx_byte_idx hits 3, we have 4 bytes. Write to RAM.
            if (rx_byte_idx == 2'd3) begin
              fifo_wr_en <= 1'b1;
              fifo_wr_addr <= rx_fifo_wr_addr[8:0];
              fifo_wr_data <= {s_axis_tdata, rx_pack_buf[23:0]};
              rx_fifo_wr_addr <= rx_fifo_wr_addr + 11'd1;
            end

            // Packet is finished (tlast)
            if (s_axis_tlast) begin
              // Write any remaining partial word to RAM
              fifo_wr_en <= 1'b1;
              fifo_wr_addr <= rx_fifo_wr_addr[8:0];
              fifo_wr_data <= {s_axis_tdata, rx_pack_buf[23:0]};

              // Calculate Plaintext Length: Total Words - Nonce(4) - AD(1) 
              // Note: Tag is handled separately via tag_buf, so it is not in ct_word_len
              ct_word_len <= rx_fifo_wr_addr + 11'd1 - 11'd9;
              state <= S_SEND_MODE;
            end
          end
        end

        // ---------------------------------------------------------
        S_SEND_MODE: begin
          state <= S_SEND_KEY;
          // Calculate total bytes to transmit back out after decryption
          if (rx_byte_idx == 2'd0) dec_total_bytes <= {ct_word_len[8:0], 2'b00};  // ct_word_len * 4 bytes
          // ct_word_len - 1 because it has encryped data less than 4 byte in its last word
          else dec_total_bytes <= {(ct_word_len - 11'd1), 2'b00} + {9'd0, rx_byte_idx};
        end

        // ---------------------------------------------------------
        S_SEND_KEY: begin
          if (key_ready) begin
            key_word_cnt <= key_word_cnt + 2'd1;
            if (key_word_cnt == 2'b11) begin
              state            <= S_SEND_NONCE;
              key_word_cnt     <= 2'd0;
              // Pre-fetch the first Nonce word from RAM for the next state
              fifo_rd_addr_reg <= 9'd1;
              nonce_word_cnt   <= 2'd1;
            end
          end
        end

        // ---------------------------------------------------------
        S_SEND_NONCE: begin
          if (bdi_ready) begin
            nonce_word_cnt   <= nonce_word_cnt + 2'd1;
            fifo_rd_addr_reg <= {7'd0, nonce_word_cnt[1:0]} + 9'd1; 	// Fetch next word
            if (nonce_word_cnt == 2'd0) begin               			// Wrap-around indicates 4 words sent
              state            <= S_SEND_AD;
              nonce_word_cnt   <= 2'd0;
              fifo_rd_addr_reg <= 9'd4;                     			// Pre-fetch AD word address
            end
          end
        end

        // ---------------------------------------------------------
        S_SEND_AD: begin
          if (bdi_ready) begin
            rx_fifo_wr_addr    <= ct_word_len;
            rx_fifo_rd_addr    <= 11'd5;
            fifo_rd_addr_reg <= 9'd5;  // Pre-fetch first Ciphertext word
            state            <= S_SEND_CIPHERTEXT;
          end
        end

        // ---------------------------------------------------------
        S_SEND_CIPHERTEXT: begin
          // Capture Decrypted Output (Plaintext) from LWC core
          if (bdo_valid && bdo_type == 4'h3) begin
            bdo_captured       <= bdo;
            bdo_capture_valid  <= 1'b1;
            bdi_valid_captured <= bdi_valid;
          end else begin
            bdo_capture_valid <= 1'b0;
          end

          // Write captured plaintext into secondary Decryption RAM
          if (bdo_capture_valid) begin
            dec_wr_en   <= 1'b1;
            dec_wr_addr <= decrypted_data_cnt[8:0];
            dec_wr_data <= bdo_captured;

            // Advance counter if full 32-bit word, else save alignment offset
            if (bdi_valid_captured == 4'd15) begin
              decrypted_data_cnt <= decrypted_data_cnt + 11'd1;
            end else begin
              decrypted_algn_cnt <= bdi_valid_captured[3] + bdi_valid_captured[2] 
                                    + bdi_valid_captured[1] + bdi_valid_captured[0];
            end
          end

          // Stream Ciphertext into LWC core
          if (rx_fifo_wr_addr <= 1) begin
            if (bdi_ready) begin
              state         <= S_SEND_TAG;
              rx_fifo_wr_addr <= 11'd4;
              rx_fifo_rd_addr <= ct_word_len + 11'd5;
            end
          end else begin
            if (bdi_ready) begin
              rx_fifo_rd_addr <= rx_fifo_rd_addr + 11'd1;
              rx_fifo_wr_addr <= rx_fifo_wr_addr - 11'd1;
              fifo_rd_addr_reg <= rx_fifo_rd_addr[8:0] + 9'd1;  // Fetch next CT word
            end
          end
        end

        // ---------------------------------------------------------
        S_SEND_TAG: begin
            // Ensure any trailing decrypted plaintext from previous state is written
          if (bdo_capture_valid) begin
            bdo_capture_valid <= 1'b0;
            dec_wr_en <= 1'b1;
            dec_wr_addr <= decrypted_data_cnt[8:0];
            dec_wr_data <= bdo_captured;
            if (bdi_valid_captured == 4'd15) begin
              decrypted_data_cnt <= decrypted_data_cnt + 11'd1;
            end else begin
              decrypted_algn_cnt <= bdi_valid_captured[3] + bdi_valid_captured[2] 
                                    + bdi_valid_captured[1] + bdi_valid_captured[0];
            end
          end
          if (bdi_ready) begin
            tag_word_cnt <= tag_word_cnt + 2'd1;
            if (tag_word_cnt == 2'd3) begin
              state         <= S_SEND2TX;
              dec_rd_addr   <= 9'd0;  // Pre-fetch first decrypted word for TX
              tx_word_addr <= 11'd0;
              rx_pack_buf   <= dec_rd_data;
            end
          end
        end

        // ---------------------------------------------------------
        S_SEND2TX: begin
          if (auth_valid && !auth) begin
            // Authentication Failed: Tag mismatch detected by ASCON
            state              <= S_IDLE;

            tx_unpack_idx       <= 2'd0;
            dec_sent_bytes     <= 11'd0;

            rx_fifo_wr_addr      <= 11'd0;
            rx_fifo_rd_addr      <= 11'd0;
            decrypted_data_cnt <= 11'd0;
            total_byte_cnt     <= 11'd0;
            rx_byte_idx  <= 2'd0;
            fifo_wr_addr       <= 9'd0;
            dec_wr_addr        <= 9'd0;
            fifo_rd_addr_reg   <= 9'd0;
            dec_rd_addr        <= 9'd0;
            key_word_cnt       <= 2'd0;
            nonce_word_cnt     <= 2'd0;
            tag_word_cnt       <= 2'd0;
            bdo_capture_valid  <= 1'b0;
          
          // Authentication Passed: Tag is verified
          end else if (auth_valid && auth) begin
            if (m_axis_tready) begin
              dec_sent_bytes <= dec_sent_bytes + 11'd1;

              // If last byte sent, reset for next packet
              if (dec_sent_bytes == dec_total_bytes - 11'd1) begin
                state              <= S_IDLE;
                tx_unpack_idx       <= 2'd0;
                dec_sent_bytes     <= 11'd0;
                rx_fifo_wr_addr      <= 11'd0;
                rx_fifo_rd_addr      <= 11'd0;
                decrypted_data_cnt <= 11'd0;
                total_byte_cnt     <= 11'd0;
                rx_byte_idx  <= 2'd0;
                fifo_wr_addr       <= 9'd0;
                dec_wr_addr        <= 9'd0;
                fifo_rd_addr_reg   <= 9'd0;
                dec_rd_addr        <= 9'd0;
                key_word_cnt       <= 2'd0;
                nonce_word_cnt     <= 2'd0;
                tag_word_cnt       <= 2'd0;
                bdo_capture_valid  <= 1'b0;

              end else if (tx_unpack_idx == 2'd3) begin
                // Move to next 32-bit word in Decryption RAM
                tx_unpack_idx  <= 2'd0;
                tx_word_addr <= tx_word_addr + 11'd1;
                rx_pack_buf   <= dec_rd_data;  // Load next word
              end else begin
                // Increment byte index within the current 32-bit word
                tx_unpack_idx <= tx_unpack_idx + 2'd1;
                // Pre-fetch the NEXT word from RAM early to avoid latency bubbles
                if (tx_unpack_idx == 2'd1) dec_rd_addr <= tx_word_addr[8:0] + 9'd1;
              end
            end
          end
        end

        default: state <= S_IDLE;
      endcase
    end
  end
endmodule

