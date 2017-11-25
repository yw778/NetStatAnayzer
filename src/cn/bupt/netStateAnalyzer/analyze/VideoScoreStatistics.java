package cn.bupt.netStateAnalyzer.analyze;

import android.util.Log;

/**
 * 影音score类评测
 * 
 */
public class VideoScoreStatistics extends ScoreStatisticsSuper {
    private final static String TAG = "VideoScoreStatistics";

    public VideoScoreStatistics() {
        this.scoreWeight = new ScoreWeight(-3.9118, 0.1203, 0.8985, 1.0053, 0, 1.906,
                0, 1.8004, 0.9876, 0, 0, 0, 0, 0, 0);
    }

    protected int dnsScore(int dns) { // unit: us
        return (int) (dns > 0 ? 11310.0 / (113.1 + 0.001 * dns) : 0);
    }

    protected int tcpScore(int tcp) { // unit: us
        return (int)(tcp > 0 ? 100.0 * Math.exp(-0.017 * tcp * 0.001) : 0);
    	//return dnsScore(tcp);
    }

    protected int respScore(int resp) { // unit: us
        return (int) (resp > 0 ? 100.0 * Math.exp(-3.879 * resp * 0.000001) : 0);
    }

    protected int delayJitterScore(double delayJitter) { // unit: us
        return (int) (delayJitter > 0 ? 10760 / (107.6 + 0.001 * delayJitter) : 0);
    }

    protected int pktLossScore(float loss) {
        return (int) (100 * (1 - loss));
    }

    protected int speedScore(long speed) { // unit: B/s
    	int s = (int) (speed > 0 ? 16.15 * Math.log( 1.41 * speed / 1024.0) : 0);
        return s > 100 ? 100 : (s > 0 ? s : 0);
    }

    @Override
    public int totalScore(PacketReader reader) {
        Log.v(TAG, "" + this.scoreWeight.weightDnsScore + " "
                + this.scoreWeight.weightTcpScore + " "
                + this.scoreWeight.weightRespScore + " "
                + this.scoreWeight.weightDelayjitterScore + " "
                + this.scoreWeight.weightPacketlossScore + " "
                + this.scoreWeight.weightSpeedScore);

        float tmp =  (float) (this.scoreWeight.weightDnsScore * dnsScore(reader.avrDns)
                + this.scoreWeight.weightTcpScore * tcpScore(reader.avrRtt)
                + this.scoreWeight.weightRespScore * respScore(reader.avrRes)
                + this.scoreWeight.weightDelayjitterScore * delayJitterScore(reader.delayJitter)
                + this.scoreWeight.weightPacketlossScore * pktLossScore(reader.pktLoss) 
                + this.scoreWeight.weightSpeedScore * speedScore(reader.avrSpeed)
        		+ this.scoreWeight.weightConstant * 100);
        
        return (int)(100 /(1 + Math.exp(-(tmp) / 100)));
    }

}
