/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
//------------------------------------------------------------------------------
// Egress L3 Rewrite
//------------------------------------------------------------------------------
table l3_rewrite {
  reads {
    ipv4 : valid;
    ipv6 : valid;
  }
  actions {
    ipv4_rewrite;
    ipv6_rewrite;
  }
}

action ipv4_rewrite() {
  add_to_field(ipv4.ttl, -1);
}

action ipv6_rewrite() {
  add_to_field(ipv6.hopLimit, -1);
}

//------------------------------------------------------------------------------
// Egress L2 rewrite
//------------------------------------------------------------------------------
table l2_rewrite {
  reads {
    l2_metadata.bd : exact;
  }
  actions {
    smac_rewrite;
  }
}

action smac_rewrite(smac) {
  modify_field(ethernet.srcAddr, smac);
}


control process_rewrite {
  apply(l2_rewrite);

  apply(l3_rewrite);
}
