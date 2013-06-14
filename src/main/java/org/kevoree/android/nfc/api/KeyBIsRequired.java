package org.kevoree.android.nfc.api;

public class KeyBIsRequired extends Exception{
	
	public KeyBIsRequired(){
		super("KEY B is required to write KEY A");
	}

}
