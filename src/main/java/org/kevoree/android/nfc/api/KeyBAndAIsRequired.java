package org.kevoree.android.nfc.api;

public class KeyBAndAIsRequired extends Exception {

	public KeyBAndAIsRequired (){
		super("Key A and Key B is required to write a new KEY B");
	}
}
