package cn.bupt.netStateAnalyzer.analyze;

import android.util.Log;

/**
 * web网络浏览器 score评测
 * 
 */
public class WebScoreStatistics extends ScoreStatisticsSuper {
    private final static String TAG = "WebScoreStatistics";

    public WebScoreStatistics() {
        this.scoreWeight = new ScoreWeight(-2.4766,0.3006, 0.6373, 1.5868, 0.3833,
                1.7611, 0.3129, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    protected int dnsScore(int dns) { // unit: us
        return (int) (dns > 0 ? 11000.0 / (110.0 + 0.001 * dns) : 0);
    }

    protected int tcpScore(int tcp) { // unit: us
        return (int)(tcp > 0 ? 100.0 * Math.exp(-0.010 * tcp * 0.001) : 0);
       
    }

    protected int respScore(int resp) { // unit: us
        return (int)(resp > 0 ? 100.0 * Math.exp(-3.879 * resp * 0.000001) : 0);
    	
    }

    protected int loadScore(long avrTime) { // unit: us
        return (int)(avrTime > 0 ? 100.0 * Math.exp(-0.08 * avrTime * 0.000001) : 0);   	
    }

    protected int speedScore(long speed) { // unit: B/s
        int s = (int) (speed > 0 ? 16.15 * Math.log( 4.9 * speed / 1024.0)  : 0);
        return s > 100 ? 100 : (s > 0 ? s : 0);
    }

    protected int trafficScore(long traffic) { // unit: B
        return (int)(traffic > 0 ? 100.0 * Math.exp(-0.80 * traffic  * 0.000001) : 0);
    }

    @Override
    public int totalScore(PacketReader reader) {
        Log.v(TAG, "" + this.scoreWeight.weightDnsScore + " "
                + this.scoreWeight.weightTcpScore + " "
                + this.scoreWeight.weightRespScore + " "
                + this.scoreWeight.weightLoadScore + " "
                + this.scoreWeight.weightSpeedScore + " "
                + this.scoreWeight.weightTrafficScore);
        Log.v("web dnsScore", " " + dnsScore(reader.avrDns));
		Log.v("web tcpScore", " " + tcpScore(reader.avrRtt));
		Log.v("web RespScore", " " + respScore(reader.avrRes));
		Log.v("web LoadScore", " " +  loadScore(reader.avrTime));
		Log.v("web speedScore", " " + speedScore(reader.avrSpeed));
		Log.v("web TrafficScore", " " + trafficScore(reader.traffic));
       
        		float tmp = (float)(this.scoreWeight.weightDnsScore * dnsScore(reader.avrDns)
                + this.scoreWeight.weightTcpScore * tcpScore(reader.avrRtt)
                + this.scoreWeight.weightRespScore * respScore(reader.avrRes)
                + this.scoreWeight.weightLoadScore * loadScore(reader.avrTime)
                + this.scoreWeight.weightSpeedScore* speedScore(reader.avrSpeed) 
                + this.scoreWeight.weightTrafficScore* trafficScore(reader.traffic)
                + this.scoreWeight.weightConstant * 100 );
        		return (int)(100 /(1 + Math.exp(-(tmp) / 100)));   
        		}
}
