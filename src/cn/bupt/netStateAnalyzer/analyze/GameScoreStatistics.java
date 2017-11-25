package cn.bupt.netStateAnalyzer.analyze;

import android.util.Log;

/**
 * 游戏类score评测 
 */
public class GameScoreStatistics extends ScoreStatisticsSuper{

	public GameScoreStatistics(){
	        this.scoreWeight = new ScoreWeight(-3.0632, 0.0446, 1.6365, 0.0968, 0, 0.1965, 1.3791, 0,
	        		0.5147, 0, 0, 0.8997, 0.9598, 0, 0);
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
    
    protected int speedScore(long speed) { // unit: B/s
    	float a = (float) (speed /1024.0 * 8);
        int s = (int) (17.36*Math.log1p(a-1)+28.29);
        return s > 100 ? 100:s;
    }
    protected int trafficScore(long traffic){// unit: B
    	float a = (float) (traffic / 1024.0);
    	int s = (int) (100 * Math.exp(-0.001107 * a));
    	return s < 0 ? 0 : s;
    }
    protected int pktLossScore(float loss) {
    	return (int) ((1 - loss) * 100);
    }
    protected int advertiseScore(int p){
    	return (int)(100-5*p);
    }
    protected int getEfficiency(float efficiency){
    	return (int)efficiency;
    }
	@Override
	public int totalScore(PacketReader reader) {
		// TODO Auto-generated method stub
		Log.d("ren","dns "+ dnsScore(reader.avrDns)
				+" tcp "+tcpScore(reader.avrRtt)
				+" resp "+respScore(reader.avrRes)
				+" pkloss "+pktLossScore(reader.pktLoss)
				+" speed "+speedScore(reader.avrSpeed)
				+" traffic "+trafficScore(reader.traffic)
				+" advertise "+advertiseScore(reader.advertise_num)
				+" effic "+getEfficiency(reader.res_efficiency));
		
		float tmp = (float)(this.scoreWeight.weightDnsScore * dnsScore(reader.avrDns)
                + this.scoreWeight.weightTcpScore * tcpScore(reader.avrRtt)
                + this.scoreWeight.weightRespScore * respScore(reader.avrRes)
                + this.scoreWeight.weightSpeedScore* pktLossScore(reader.pktLoss)
                + this.scoreWeight.weightSpeedScore* speedScore(reader.avrSpeed) 
                + this.scoreWeight.weightTrafficScore* trafficScore(reader.traffic)
                + this.scoreWeight.weightAdvertise* advertiseScore(reader.advertise_num)
				+ this.scoreWeight.weightEfficiency* getEfficiency(reader.res_efficiency)
				+ this.scoreWeight.weightConstant * 100
                );
		
		return (int)(100 /(1 + Math.exp(-(tmp) / 100)));   
	}

}
