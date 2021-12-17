package com.shree;

import java.util.ArrayList;

public class SingletonClass {
    ArrayList<String> datesList = new ArrayList<String>();
    ArrayList<String> timeList = new ArrayList<String>();
    ArrayList<String> sourceList = new ArrayList<String>();
    ArrayList<String> destinationList = new ArrayList<String>();
    ArrayList<String> flagList = new ArrayList<String>();
    private static SingletonClass singletonClass;

    private SingletonClass(){

    }
   
    public static SingletonClass getInstance()
  {
    if (singletonClass == null)
    {
      
      synchronized (SingletonClass.class)
      {
        if(singletonClass==null)
        {
          singletonClass = new SingletonClass();
        }
       
      }
    }
    return singletonClass;
  }
}
