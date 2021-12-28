package com.shree;



public class SomeDailyJob implements Runnable {
   public void run(){
    GetStix getStix=GetStix.getInstance();
    getStix.getStixx();
   }
}
