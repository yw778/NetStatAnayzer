package cn.bupt.netStateAnalyzer.pcap;

import android.util.Log;

/**
 * Connection
 * 地址操作以及转化
 * 
 */
public class Connection {
    public String src;
    public String spt;
    public String dst;
    public String dpt;
    public String uid;


    public Connection(String line, String type) {
        line = line.trim();
        Log.i("address",line);
        String[] fields = line.split("\\s+", 10);
        String src[] = fields[1].split(":", 2);
        String dst[] = fields[2].split(":", 2);
        if (type.endsWith("6")) {
            this.src = getAddress6(src[0]);
            this.dst = getAddress6(dst[0]);
        } else {
            this.src = getAddress(src[0]);
            this.dst = getAddress(dst[0]);
        }
        this.spt = String.valueOf(getInt16(src[1]));
        this.dpt = String.valueOf(getInt16(dst[1]));
        this.uid = fields[7];
    }


    private final String getAddress(final String hexa) {
        try {
            final long v = Long.parseLong(hexa, 16);
            final long adr = (v >>> 24) | (v << 24) | ((v << 8) & 0x00FF0000)
                    | ((v >> 8) & 0x0000FF00);
            return ((adr >> 24) & 0xff) + "." + ((adr >> 16) & 0xff) + "."
                    + ((adr >> 8) & 0xff) + "." + (adr & 0xff);
        } catch (Exception e) {
            Log.w("NetworkLog", e.toString(), e);
            return "-1.-1.-1.-1";
        }
    }


    private final String getAddress6(final String hexa) {
        try {
            final String ip4[] = hexa.split("0000000000000000FFFF0000");

            if (ip4.length == 2) {
                final long v = Long.parseLong(ip4[1], 16);
                final long adr = (v >>> 24) | (v << 24)
                        | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00);
                return ((adr >> 24) & 0xff) + "." + ((adr >> 16) & 0xff) + "."
                        + ((adr >> 8) & 0xff) + "." + (adr & 0xff);
            } else {
                return "-2.-2.-2.-2";
            }
        } catch (Exception e) {
            Log.w("NetworkLog", e.toString(), e);
            return "-1.-1.-1.-1";
        }
    }


    private final int getInt16(final String hexa) {
        try {
            return Integer.parseInt(hexa, 16);
        } catch (Exception e) {
            Log.w("NetworkLog", e.toString(), e);
            return -1;
        }
    }
}
