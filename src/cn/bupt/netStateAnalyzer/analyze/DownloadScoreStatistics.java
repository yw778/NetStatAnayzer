package cn.bupt.netStateAnalyzer.analyze;

import android.util.Log;

/**
 * 下载类的Score评测
 * 
 * 
 * 
 */
public class DownloadScoreStatistics extends ScoreStatisticsSuper {
    private final static String TAG = "DownloadScoreStatistics";
    
    public DownloadScoreStatistics() {
        this.scoreWeight = new ScoreWeight(-4.1907, 0.4421, 0.7193, 0, 0, 2.2969, 0, 0,
                1.8061, 1.4386, 0.2724, 0, 0, 0, 0);
    }

    protected int dnsScore(int dns) { // unit: us
        return (int) (dns > 0 ? 11000 / (110.0 + 0.001 * dns) : 0);
    }

    protected int tcpScore(int tcp) { // unit: us
        return (int) (100.0 * Math.exp(-0.010 * tcp * 0.001));
    }

    protected int downloadScore(long avrTime) { // unit: us
        return (int) (avrTime > 0 ? 100.0 * Math.exp(-0.08 * avrTime * 0.000001) : 0);
    }

    protected int speedScore(long speed) { // unit: B/s
    	int s = (int) (speed > 0 ? 16.15 * Math.log( 4.9 * speed / 1024.0) : 0);
        return s > 100 ? 100 : (s > 0 ? s : 0);
    }

    protected int multiThreadScore(int threadNum) {
       
    	return (int) (Math.min(75 + 5 * threadNum, 100 ));
    }

    protected int pktlossScore(float plr) { // unit: B
        return (int) ((1 - plr) * 100);
    }

    @Override
    public int totalScore(PacketReader reader) {
        Log.v(TAG, "" + this.scoreWeight.weightDnsScore + " "
                + this.scoreWeight.weightTcpScore + " "
                + this.scoreWeight.weightDownloadScore + " "
                + this.scoreWeight.weightMultithreadScore + " "
                + this.scoreWeight.weightSpeedScore + " "
                + this.scoreWeight.weightPacketlossScore);
        Log.v("trade dnsScore", " " + dnsScore(reader.avrDns));
		Log.v("trade tcpScore", " " + tcpScore(reader.avrRtt));
		Log.v("trade downloadScore", " " + downloadScore(reader.avrTime));
		Log.v("trade multiThreadScore", " " +  multiThreadScore(reader.threadNum));
		Log.v("trade speedScore", " " + speedScore(reader.avrSpeed));
		Log.v("trade pktlossScore", " " + pktlossScore(reader.pktLoss));

		float tmp = (float) (this.scoreWeight.weightDnsScore * dnsScore(reader.avrDns)
                + this.scoreWeight.weightTcpScore * tcpScore(reader.avrRtt)
                + this.scoreWeight.weightDownloadScore * downloadScore(reader.avrTime)
                + this.scoreWeight.weightMultithreadScore * multiThreadScore(reader.threadNum)
                + this.scoreWeight.weightSpeedScore * speedScore(reader.avrSpeed) 
                + this.scoreWeight.weightPacketlossScore * pktlossScore(reader.pktLoss)
                + this.scoreWeight.weightConstant * 100);
        return (int)(100 /(1 + Math.exp(-(tmp) / 100)));    }
}
