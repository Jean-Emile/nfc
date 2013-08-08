package org.kevoree.android.nfc.impl;

import java.math.BigInteger;
import java.nio.charset.Charset;

import android.content.Intent;
import android.nfc.TagLostException;
import org.kevoree.android.nfc.api.INfc;

public class NFC_Mifare_classic implements INfc {

    private boolean AUTHORIZATION_TO_WRITE_IN_SECTOR_TRAILER = false;


    /**
     * Write data to a block of a sector of the chip (16 bytes)
     *
     * @param sector : Sector that we want to write
     * @param block : Block that we want to write
     * @param data : Data that we want to write in a block (hexadecimal 16bytes)
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to write
     * @return true if data has been sent
     * @throws TagActionException
     */
    public boolean writeInABlock(int sector, int block, String data, byte[] key, boolean useAsKeyB) throws TagActionException {
        int result = 0;
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {

            // if sector index is not on the chip
            if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
                mcReader.close();
                throw new TagActionException("Sector should be between 0 and mcReader.getSectorCount()-1");
            }

            // if block index is not on the sector
            if (block < 0 && block > mcReader.getBlockCount() - 1) {
                mcReader.close();
                throw new TagActionException("Block should be between 0 and mcReader.getBlockCount()-1");
            }

            // If data does not contain 32 characters with only hexadecimal characters
            if (Common.isHexAnd16Byte(data, null) == false) {
                mcReader.close();
                throw new TagActionException("Data length should be 32 characters and contain only hexadecimal characters");
            }

            //  if the block is a systemBlock(sectorTrailer)
            if (block == 3 || block == 15) {
                mcReader.close();
                throw new TagActionException("the block is a System Block");
            }
            // if the block is the ID block
            if (sector == 0 && block == 0) {
                mcReader.close();
                throw new TagActionException("the block is the ID block");

            }
            // It's OK to write on NFC chip
            result = mcReader.writeBlock(sector, block, Common.hexStringToByteArray(data), key, useAsKeyB);
            mcReader.close();

            // if result == 0, there is not error
            if (result == 0) {
                return true;
            } else if (result == 4) {
                throw new TagActionException("Unable to authenticate with this KEY");
            } else if (result == -1) {
                throw new TagActionException("Error while writing on NFC chip");
            }

        }
        throw new TagActionException("Unable to connect with NFC chip");

    }

    /**
     * Write data to a blockTrailer of a sector of the chip (16 bytes) (16 bytes)
     *
     * @param sector : Sector that we want to write
     * @param block : Block that we want to write
     * @param data : Data that we want to write in a block (hexadecimal 16bytes)
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to write
     * @return true if data has been sent
     * @throws TagActionException
     */
    private boolean writeInBlockTrailer(int sector, int block, String data, byte[] key, boolean useAsKeyB) throws TagActionException {
        int result = 0;
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {

            // if sector index is not on the chip
            if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
                mcReader.close();
                throw new TagActionException("Sector should be between 0 and mcReader.getSectorCount()-1");
            }

            // If block is not System block (SextorTrailer)
            if (block != 3 && block != 15) {
                mcReader.close();
                throw new TagActionException("the block is not a SectorTrailer");

            }

            // If data does not contain 32 characters with only hexadecimal characters
            if (Common.isHexAnd16Byte(data, null) == false) {
                mcReader.close();
                throw new TagActionException("Data length should be 32 characters and contain only hexadecimal characters");

            }

            // It's OK to write on NFC chip
            result = mcReader.writeBlock(sector, block, Common.hexStringToByteArray(data), key, useAsKeyB);
            mcReader.close();

            // if result == 0, there is not error
            if (result == 0) {
                return true;
            } else if (result == 4) {
                throw new TagActionException("Unable to authenticate with this KEY");
            } else if (result == -1) {
                throw new TagActionException("Error while writing on NFC chip");
            }
        }
        throw new TagActionException("Unable to connect with NFC chip");
    }

    /**
     * Write data to a sector of the chip. We can write 32 bytes in sector 1 (block 1 & 2) ans 48 bytes in other sector (block 0, 1 & 2)
     *
     * @param sector : Sector that we want to write
     * @param data : Data that we want to write in a sector (hexa)
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to write
     * @return true if data has been sent
     * @throws TagActionException
     */
    public boolean writeInASector(int sector, String data, byte[] key, boolean useAsKeyB) throws TagActionException {
        int result = -1;

        // get MCReader
        MCReader mcReader = Common.checkForTagAndCreateReader(null);

        if (mcReader != null) {
            // if sector index is not on the chip
            if (sector < 0 && sector > mcReader.getSectorCount() - 1) {
                mcReader.close();
                throw new TagActionException("Sector should be between 0 and mcReader.getSectorCount()-1");
            }

            // If it's sector 0 we can write only 32 bytes (bloc 2 et 3)
            if (sector == 0) {
                if (Common.isHexAnd32Byte(data, null) == false) {
                    mcReader.close();
                    throw new TagActionException("Data length should be 64 characters and contain only hexadecimal characters");
                }

            } else if (Common.isHexAnd48Byte(data, null) == false) {
                // other sectors, we can write 48 bytes
                mcReader.close();
                throw new TagActionException("Data length should be 96 characters and contain only hexadecimal characters");
            }

            int i = 0;

            if (sector == 0) {
                for (int j = 1; j < 3; j++) {

                    String string = (data.subSequence(i, i + 32).toString());

                    result = mcReader.writeBlock(sector, j, Common.hexStringToByteArray(string), key, useAsKeyB);
                    if (result != 0) {
                        if (result == -1) {
                            mcReader.close();
                            throw new TagActionException("Error while writing on NFC chip");
                        } else if (result == 4) {
                            mcReader.close();
                            throw new TagActionException("Unable to authenticate to sector : "+sector  +" with this KEY");
                        } else {
                            mcReader.close();
                            throw new TagActionException("Error");
                        }
                    }
                    i = i + 32;
                }
                mcReader.close();
            } else {

                for (int j = 0; j < 3; j++) {
                    String string = (data.subSequence(i, i + 32).toString());
                    result = mcReader.writeBlock(sector, j, Common.hexStringToByteArray(string), key, useAsKeyB);
                    if (result != 0) {
                        if (result == -1) {
                            mcReader.close();
                            throw new TagActionException("Error while writing on NFC chip");
                        } else if (result == 4) {
                            mcReader.close();
                            throw new TagActionException("Unable to authenticate to sector : "+sector  +" with this KEY");
                        } else {
                            mcReader.close();
                            throw new TagActionException("Error");
                        }
                    }
                    i = i + 32;
                }
                mcReader.close();
            }

            if (result == 0) {
                return true;
            }
        }
        throw new TagActionException("Unable to connect with NFC chip");

    }

    /**
     * Write in all space of NFC Chip (752bytes for  MifareClassic 1K). For this, we need to have the same key for all sectors
     *
     * @param data : Data that we want to write(hexa)
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to write
     * @return true if data has been sent
     */
    public boolean writeInAllDataSpace(String data, byte[] key, boolean useAsKeyB) throws TagActionException {
        int result = 0;

        MCReader mcReader = Common.checkForTagAndCreateReader(null);


        if (mcReader != null) {

            if (data.length() < 1504) {             // TODO : Remove
                while (data.length() != 1504) {
                    data = data + "0";
                }
            }

            if (!(Common.isHexAnd752Byte(data, null))) {
                mcReader.close();
                throw new TagActionException("Data length should be 752 characters and contain only hexadecimal characters");

            }
            int k = 0;

            for (int j = 0; j < mcReader.getSectorCount(); j++) {

                if (j == 0) {
                    // secteur 0
                    for (int i = 1; i < mcReader.getBlockCountInSector(j) - 1; i++) {

                        String string = (data.subSequence(k, k + 32).toString());

                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key, useAsKeyB);

                        if (result != 0) {
                            if (result == -1) {
                                mcReader.close();
                                throw new TagActionException("Error while writing on NFC chip");
                            } else if (result == 4) {
                                mcReader.close();
                                throw new TagActionException("Unable to authenticate to sector : "+j  +" with this KEY");
                            } else {
                                mcReader.close();
                                throw new TagActionException("Error");
                            }
                        }
                        k = k + 32;
                    }
                    mcReader.close();
                } else {
                    // other sectors
                    for (int i = 0; i < mcReader.getBlockCountInSector(j) - 1; i++) {

                        String string = (data.subSequence(k, k + 32).toString());

                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key, useAsKeyB);

                        if (result != 0) {
                            if (result == -1) {
                                mcReader.close();
                                throw new TagActionException("Error while writing on NFC chip");
                            } else if (result == 4) {
                                mcReader.close();
                                throw new TagActionException("Unable to authenticate to sector : "+j  +" with this KEY");
                            } else {
                                mcReader.close();
                                throw new TagActionException("Error");
                            }
                        }
                        k = k + 32;
                    }
                    mcReader.close();
                }
            }

            if (result == 0) {
                return true;
            }
        }
        throw new TagActionException("Unable to connect with NFC chip");

    }

    /**
     * Write in all space of NFC Chip (752bytes for  MifareClassic 1K). For this, we need to have the same key for all sectors
     *
     * @param data : Data that we want to write(hexa)
     * @param key : All Keys for the authentication  (byte of keys)
     * @param useAsKeyB : true if we use Key B to write
     * @return true if data has been sent
     */
    public boolean writeInAllDataSpaceWithAllKey(String data, byte[][] key, boolean useAsKeyB) throws TagActionException {
        int result = 0;

        MCReader mcReader = Common.checkForTagAndCreateReader(null);

        if (mcReader != null) {
            if (data.length() < 1504) {
                while (data.length() != 1504) {
                    data = data + "0";
                }
            }

            if (!(Common.isHexAnd752Byte(data, null))) {
                mcReader.close();
                throw new TagActionException("Data length should be 752 characters and contain only hexadecimal characters");

            }
            int k = 0;

            for (int j = 0; j < mcReader.getSectorCount(); j++) {

                if (j == 0) {
                    // sector 0
                    for (int i = 1; i < mcReader.getBlockCountInSector(j) - 1; i++) {

                        String string = (data.subSequence(k, k + 32).toString());

                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key[j], useAsKeyB);

                        if (result != 0) {
                            if (result == -1) {
                                mcReader.close();
                                throw new TagActionException("Error while writing on NFC chip");
                            } else if (result == 4) {
                                mcReader.close();
                                throw new TagActionException("Unable to authenticate to sector : "+j  +" with this KEY");
                            } else {
                                mcReader.close();
                                throw new TagActionException("Error");
                            }
                        }
                        k = k + 32;
                    }

                } else {
                    // other sector
                    for (int i = 0; i < mcReader.getBlockCountInSector(j) - 1; i++) {

                        String string = (data.subSequence(k, k + 32).toString());

                        result = mcReader.writeBlock(j, i, Common.hexStringToByteArray(string), key[j], useAsKeyB);

                        if (result != 0) {
                            if (result == -1) {
                                mcReader.close();
                                throw new TagActionException("Error while writing on NFC chip");
                            } else if (result == 4) {
                                mcReader.close();
                                throw new TagActionException("Unable to authenticate to sector : "+j  +" with this KEY");
                            } else {
                                mcReader.close();
                                throw new TagActionException("Error");
                            }
                        }
                        k = k + 32;
                    }
                }
            }

            if (result == 0) {

                return true;
            }
        }
        throw new TagActionException("Unable to connect with NFC chip");

    }

    /**
     * Write AccesBits of Sector Trailer with Key A & B
     *
     * @param sector : Sector that we want to write AccessBits
     * @param keyA : Key A  for this sector
     * @param keyB : Key B  for this sector
     * @param newAccessBit : new AccesBits for SectorTrailer
     * @return true if data has been sent
     * @throws TagActionException
     */
    public boolean writeAccessBit(int sector, byte[] keyA, byte[] keyB, byte[] newAccessBit) throws TagActionException {
        if (isAuthorizationToWriteInSectorTrailer()) {
            this.setAuthorizationToWriteInSectorTrailer(false);

            // Recovery of SectorTrailer of sector
            String result = this.readABlock(sector, 3, keyA, false);

            if (result != null) {
                // Recovery parameters for sector
                byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
                byte[][] AC = Common.acToACMatrix(ac);

                // Reading permissions of sector Trailer
                int permission = this.ReadAccessBits(AC[0][3], AC[1][3], AC[2][3], true);

                // Checking permissions
                if (!(permission == 13 || permission == 14 || permission == 15)) {
                    throw new TagActionException("We can't write AccesBits with this parameters");
                }
                if (permission == 13) {
                    String bloc = Common.byte2HexString(keyA) + Common.byte2HexString(newAccessBit) + result.substring(20, 32);

                    // Write with KEY A
                    return this.writeInBlockTrailer(sector, 3, bloc, keyA, false);
                } else if (permission == 14 || permission == 15) {
                    // Write with KEY B
                    String bloc = Common.byte2HexString(keyA) + Common.byte2HexString(newAccessBit) + Common.byte2HexString(keyB);

                    return this.writeInBlockTrailer(sector, 3, bloc, keyB, true);
                }
            }
            throw new TagActionException("Unable to connect with NFC chip");
        }
        throw new TagActionException("You don't have authorization to write in SectorTrailer");
    }

    /**
     * Modify KeyA of 1 Sector with Key A & B
     *
     * @param sector : Sector that we want to write KeyA
     * @param keyA : Key A  for this sector
     * @param keyB : Key B  for this sector
     * @param newKeyA : the new KeyA
     * @return true si les données on bien été transmise
     * @throws TagActionException
     */
    public boolean writeKeyA(int sector, byte[] keyA, byte[] keyB, byte[] newKeyA) throws TagActionException {

        // Getting SectorTrailer of sector
        String result = this.readABlock(sector, 3, keyA, false);

        if (result != null) {
            // Getting parameters for the sector
            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
            byte[][] AC = Common.acToACMatrix(ac);

            // Reading permissions of sector Trailer
            int permission = this.ReadAccessBits(AC[0][3], AC[1][3], AC[2][3], true);

            // Checking permissions
            if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
                throw new TagActionException("We can't write KEYA with this parameters");
            }

            // if Permission = 9, 13, 11 or 14 we can write new KeyB
            if (permission == 9 || permission == 13) {
                String bloc = Common.byte2HexString(newKeyA) + result.subSequence(12, 32);
                // writing with key A
                return this.writeInBlockTrailer(sector, 3, bloc, keyA, false);
            } else if (permission == 11 || permission == 14) {
                String bloc = Common.byte2HexString(newKeyA) + result.subSequence(12, 20) + Common.byte2HexString(keyB);
                // writing with Key B
                return this.writeInBlockTrailer(sector, 3, bloc, keyB, true);
            }
        }
        throw new TagActionException("Unable to connect with NFC chip");
    }


    /**
     * Modify KeyB of 1 Sector with Key A & B
     *
     * @param sector : Sector that we want to write KeyB
     * @param keyA : Key A  for this sector
     * @param keyB : Key B  for this sector
     * @param newKeyB : the new KeyB
     * @return true si les données on bien été transmise
     * @throws TagActionException
     */
    public boolean writeKeyB(int sector, byte[] keyA, byte[] keyB, byte[] newKeyB) throws TagActionException {

        String result = this.readABlock(sector, 3, keyA, false);

        if (result != null) {
            // Getting parameters for the sector
            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
            byte[][] AC = Common.acToACMatrix(ac);

            // Reading permissions of sector Trailer
            int permission = this.ReadAccessBits(AC[0][3], AC[1][3], AC[2][3], true);

            // Checking permissions
            if (!(permission == 9 || permission == 11 || permission == 13 || permission == 14)) {
                throw new TagActionException("We can't write KEYA with this parameters");
            }

            // if Permission = 9,13,11 or 14 we can write new KeyA
            if (permission == 9 || permission == 13) {
                String bloc = Common.byte2HexString(keyA) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);

                // writing with key A
                return this.writeInBlockTrailer(sector, 3, bloc, keyA, false);

            } else if (permission == 11 || permission == 14) {
                String bloc = Common.byte2HexString(keyA) + result.subSequence(12, 20) + Common.byte2HexString(newKeyB);

                // writing with Key B
                return this.writeInBlockTrailer(sector, 3, bloc, keyB, true);

            }

        }
        throw new TagActionException("Unable to connect with NFC chip");
    }

    // ////////////////////////////////////////////////////////////

    // Read the NFC Chip

    // ////////////////////////////////////////////////////////////

    /**
     * Get ID of NFC TAG
     *
     * @return ID of TAG (String)
     */
    public String getId() {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            mcReader.close();
            return Common.byte2HexString(Common.getUID());
        }
        return "No ID discovered !";
    }

    /**
     * Read a block of a sector of the nfc chip
     *
     * @param sector : Sector that we want to read
     * @param block : Block that we want to read
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to read
     * @return value of the block (hexadecimal)
     */
    public String readABlock(int sector, int block, byte[] key, boolean useAsKeyB) throws TagActionException {

        MCReader mcReader = Common.checkForTagAndCreateReader(null);

        String[] result = null;
        // * Reading the block
        if (mcReader != null) {
            if (sector < 0 || sector > mcReader.getSectorCount() - 1) {
                mcReader.close();
                throw new TagActionException("Sector should be between 0 and mcReader.getSectorCount()-1");
            }
            if (block < 0 || block > mcReader.getBlockCountInSector(sector) - 1) {
                mcReader.close();
                throw new TagActionException("Block should be between 0 and mcReader.getBlockCount()-1");
            }

            try {
                result = mcReader.readSector(sector, key, useAsKeyB);

            } catch (TagLostException e) {
                mcReader.close();
                e.printStackTrace();
                throw new TagActionException(e.getMessage());
            }
            if (result != null) {
                mcReader.close();
                return result[block];
            }
            mcReader.close();
            throw new TagActionException("Unable to authenticate to sector : "+sector  +" with this KEY");
        }
        throw new TagActionException("Unable to connect with NFC chip");
    }

    /**
     *  Read a sector of the nfc chip
     *
     * @param sector : Sector that we want to read
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to read
     * @return value of the sector (hexadecimal)
     */
    public String readASector(int sector, byte[] key, boolean useAsKeyB) throws TagActionException {

        // connect to NFC chip
        MCReader mcReader = Common.checkForTagAndCreateReader(null);

        if (mcReader != null) {
            // * Lecture bloc par bloc de la puce NFC avec clé par défaut
            if (sector < 0 || sector > mcReader.getSectorCount() - 1) {
                mcReader.close();
                throw new TagActionException("Sector should be between 0 and mcReader.getSectorCount()-1");
            }
            String[] dataPuce = null;

            try {
                dataPuce = mcReader.readSector(sector, key, useAsKeyB);
            } catch (TagLostException e) {
                mcReader.close();
                e.printStackTrace();
                throw new TagActionException(e.getMessage());
            }

            String data = "";
            if (dataPuce != null) {

                for (int j = 0; j < mcReader.getBlockCountInSector(sector); j++) {
                    data += dataPuce[j];
                }
                mcReader.close();
                return data;
            }
            mcReader.close();
            throw new TagActionException("Unable to authenticate to sector : "+sector  +" with this KEY");
        }
        throw new TagActionException("Unable to connect with NFC chip");
    }

    /**
     * Read all of the nfc chip.
     * For this, we need to have the same key for all sectors
     *
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to read
     * @return value of the NFC chip (hexadecimal)
     */
    public String readAllSpace(byte[] key, boolean useAsKeyB) throws TagActionException {
        // connect to NFC chip
        MCReader mcReader = Common.checkForTagAndCreateReader(null);

        // * Lecture bloc par bloc de la puce NFC avec clé par défaut

        String[][] string = new String[100][4];

        String[] string2 = null;
        if (mcReader != null) {

            for (int i = 0; i < mcReader.getSectorCount(); i++) {

                try {
                    string2 = mcReader.readSector(i, key, useAsKeyB);
                } catch (TagLostException e) {
                    e.printStackTrace();
                    throw new TagActionException(e.getMessage());

                }

                if (string2 != null) {
                    string[i][0] = string2[0];
                    string[i][1] = string2[1];
                    string[i][2] = string2[2];
                    string[i][3] = string2[3];
                } else {
                    mcReader.close();
                    throw new TagActionException("Unable to authenticate to sector : "+i  +" with this KEY");
                }
            }

            String data = "";

            for (int i = 0; i < mcReader.getSectorCount(); i++) {

                for (int j = 0; j < mcReader.getBlockCountInSector(i); j++) {
                    data += string[i][j];
                }

            }

            mcReader.close();
            return data;
        }
        throw new TagActionException("Unable to connect with NFC chip");

    }

    /**
     * Get count of block of the NFC chip
     *
     * @return number of block of the NFC chip
     */
    public int getBlockCount() {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            int x = mcReader.getBlockCount();
            mcReader.close();
            return x;
        }
        return -1;
    }

    /**
     * Get count of sector of the NFC chip
     *
     * @return number of sector of the NFC chip
     */
    public int getSectorCount() {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            int x = mcReader.getSectorCount();
            mcReader.close();
            return x;
        }
        return -1;
    }

    /**
     * Get count of block in a sector of the NFC chip
     *
     * @param sector : Sector whose we want to know the count of block
     * @return number of block in the sector of the NFC chip
     */
    public int getBlockCountInSector(int sector) {
        MCReader mcReader = Common.checkForTagAndCreateReader(null);
        if (mcReader != null) {
            int x = mcReader.getBlockCountInSector(sector);
            mcReader.close();
            return x;
        }
        return -1;
    }

    /**
    * Get information for a block
    *
    * @param sector : Sector
    * @param block : Block that we want to get information
    * @param key : Key for the authentication
    * @param useAsKeyB : true if we use Key B to write
    * @return <ul>
    *         <li>Data Block</li>
    *         <ul>
        *         <li>1 : Read Write Increment Decrement with key A or B</li>
        *         <li>2 : Read with key A or B</li>
        *         <li>3 : Read with key A or B and Write with key B only</li>
        *         <li>4 : Read Write Increment Decrement with B and read + decrement with key A</li>
        *         <li>5 : Read Decrement with key A or B</li>
        *         <li>6 : Read Write with key B</li>
        *         <li>7 : Read with key B</li>
        *         <li>8 : Never</li>
    *         </ul>
    *         <li>Sector Trailer (We can never read Key A)</li>
    *         <ul>
        *         <li>9 : Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A</li>
        *         <li>10 : Read Acces Bits and Read Key B oncly with KEY A</li>
        *         <li>11 : write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A</li>
        *         <li>12 : Read Acces bits with KEY A or KEY B</li>
        *         <li>13 : Write KEY A and B, Read/Write Acces bits and read KEY B with "KEY A"</li>
        *         <li>14 : Write KEY A and B, Read/Write Acces bits with "KEY B" and read Acces Bits with "KEY A" too</li>
        *         <li>15 : Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too</li>
        *         <li>16 : Read Acces Bits with KEY A or B</li>
    *         </ul>
    *
    *         <li>-1 : error</li> </ul>
    * @throws TagActionException
    */
    public int getInfoForBlock(int sector, int block, byte[] key, boolean useAsKeyB) throws TagActionException {

        // Reading of sector trailer
        String result = this.readABlock(sector, 3, key, useAsKeyB);

        if (result != null) {
            // Get parameters for sector
            byte[] ac = Common.hexStringToByteArray(result.subSequence(12, 20).toString());
            byte[][] AC = Common.acToACMatrix(ac);

            boolean trailer;
            if (block != 3) {
                trailer = false;
            } else {
                trailer = true;
            }
            // Get permissions for block
            int permission = this.ReadAccessBits(AC[0][block], AC[1][block], AC[2][block], trailer);
            return permission;
        }
        return -1;
    }

    /**
     * Get information of three access bits
     *
     * @param c1 : bit 1
     * @param c2 : bit 2
     * @param c3 : bit 3
     * @param isSectorTrailer :True if block is SectorTrailer
     * @return
     *
     *         <ul>
     *         <li>Data Block</li>
     *         <ul>
     *         <li>1 : Read Write Increment Decrement with key A or B</li>
     *         <li>2 : Read with key A or B</li>
     *         <li>3 : Read with key A or B and Write with key B only</li>
     *         <li>4 : Read Write Increment Decrement with B and read + decrement with key A</li>
     *         <li>5 : Read Decrement with key A or B</li>
     *         <li>6 : Read Write with key B</li>
     *         <li>7 : Read with key B</li>
     *         <li>8 : Never</li>
     *         </ul>
     *         <li>Sector Trailer (We can never read Key A)</li>
     *         <ul>
     *         <li>9 : Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A</li>
     *         <li>10 : Read Acces Bits and Read Key B oncly with KEY A</li>
     *         <li>11 : write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A</li>
     *         <li>12 : Read Acces bits with KEY A or KEY B</li>
     *         <li>13 : Write KEY A and B, Read/Write Acces bits and read KEY B with "KEY A"</li>
     *         <li>14 : Write KEY A and B, Read/Write Acces bits with "KEY B" and read Acces Bits with "KEY A" too</li>
     *         <li>15 : Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too</li>
     *         <li>16 : Read Acces Bits with KEY A or B</li>
     *         </ul>
     *
     *         <li>-1 : error</li> </ul>
     *
     */
    public int ReadAccessBits(byte c1, byte c2, byte c3, boolean isSectorTrailer) {
        if (isSectorTrailer == false) {
            if (c1 == 0) {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 000

                        return 1;
                    } else {
                        // 001
                        return 5;
                    }
                } else {
                    if (c3 == 0) {
                        // 010
                        return 2;
                    } else {
                        // 011
                        return 6;
                    }
                }
            } else {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 100
                        return 3;
                    } else {
                        // 101
                        return 7;
                    }
                } else {
                    if (c3 == 0) {
                        // 110
                        return 4;
                    } else {
                        // 111
                        return 8;
                    }
                }
            }
        } else {
            if (c1 == 0) {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 000
                        return 9;
                    } else {
                        // 001
                        return 13;
                    }
                } else {
                    if (c3 == 0) {
                        // 010
                        return 10;
                    } else {
                        // 011
                        return 14;
                    }
                }
            } else {
                if (c2 == 0) {
                    if (c3 == 0) {
                        // 100
                        return 11;
                    } else {
                        // 101
                        return 15;
                    }
                } else {
                    if (c3 == 0) {
                        // 110
                        return 12;
                    } else {
                        // 111
                        return 16;
                    }
                }
            }
        }

    }

    /**
     * Creation of 4 bytes  of access bits for the sectorTrailer
     *
     * @Explication <ul>
     *              <li>Data Block</li>
     *              <ul>
     *              <li>1 : Read Write Increment Decrement with key A or B</li>
     *              <li>2 : Read with key A or B</li>
     *              <li>3 : Read with key A or B and Write with key B only</li>
     *              <li>4 : Read Write Increment Decrement with B and read + decrement with key A</li>
     *              <li>5 : Read Decrement with key A or B</li>
     *              <li>6 : Read Write with key B</li>
     *              <li>7 : Read with key B</li>
     *              <li>8 : Never</li>
     *              </ul>
     *              <li>Sector Trailer (We can never read Key A)</li>
     *              <ul>
     *              <li>9 : Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A</li>
     *              <li>10 : Read Acces Bits and Read Key B oncly with KEY A</li>
     *              <li>11 : write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A</li>
     *              <li>12 : Read Acces bits with KEY A or KEY B</li>
     *              <li>13 : Write KEY A and B, Read/Write Acces bits and read KEY B with "KEY A"</li>
     *              <li>14 : Write KEY A and B, Read/Write Acces bits with "KEY B" and read Acces Bits with "KEY A" too</li>
     *              <li>15 : Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too</li>
     *              <li>16 : Read Acces Bits with KEY A or B</li>
     *              </ul>
     *
     *
     * @param permB0 : permission for block 0 between 1 et 8
     * @param permB1 : permission for block 1 between 1 et 8
     * @param permB2 : permission for block 2 between 1 et 8
     * @param permSectorTrailer : : permission for block 3 (sector Trailer) between 9 et 16
     * @return 4 bytes of AccesBit of SectorTrailer
     */
    public byte[] createAccessBit(int permB0, int permB1, int permB2, int permSectorTrailer) {

        String[] block0 = getAccessbit(permB0);
        String[] block1 = getAccessbit(permB1);
        String[] block2 = getAccessbit(permB2);
        String[] block3 = getAccessbit(permSectorTrailer);

        String accessBit = not(block3[1]) + not(block2[1]) + not(block1[1]) + not(block0[1]) + not(block3[0]) + not(block2[0]) + not(block1[0])
                + not(block0[0]) + block3[0] + block2[0] + block1[0] + block0[0] + not(block3[2]) + not(block2[2]) + not(block1[2]) + not(block0[2])
                + block3[2] + block2[2] + block1[2] + block0[2] + block3[1] + block2[1] + block1[1] + block0[1] + "01101001";

        String valHex = Long.toString(Long.parseLong(accessBit,2),16);

        return Common.hexStringToByteArray(valHex);

    }


    /**
     * Get 3 bits of AccessBit for a permission
     *
     * @param permission
     * @return String Array of three accessbits
     */
    private String[] getAccessbit(int permission) {
        String[] retour = new String[3];

        if (permission == 1 || permission == 9) {
            retour[0] = "0";
            retour[1] = "0";
            retour[2] = "0";

            return retour;

        } else if (permission == 2 || permission == 10) {
            retour[0] = "0";
            retour[1] = "1";
            retour[2] = "0";

            return retour;

        } else if (permission == 3 || permission == 11) {
            retour[0] = "1";
            retour[1] = "0";
            retour[2] = "0";

            return retour;

        } else if (permission == 4 || permission == 12) {
            retour[0] = "1";
            retour[1] = "1";
            retour[2] = "0";

            return retour;

        } else if (permission == 5 || permission == 13) {
            retour[0] = "0";
            retour[1] = "0";
            retour[2] = "1";

            return retour;

        } else if (permission == 6 || permission == 14) {
            retour[0] = "0";
            retour[1] = "1";
            retour[2] = "1";

            return retour;

        } else if (permission == 7 || permission == 15) {
            retour[0] = "1";
            retour[1] = "0";
            retour[2] = "1";

            return retour;

        } else {
            retour[0] = "1";
            retour[1] = "1";
            retour[2] = "1";

            return retour;
        }

    }

    // ////////////////////////////////////////////////////////////

    // Other  method

    // ////////////////////////////////////////////////////////////

    /**
     * Convert hexadecimal string to an ascii string
     *
     * @param s : hexadecimal string to convert
     * @return ascii string
     */
    public String hexToAscii(String s) {
        int n = s.length();
        StringBuilder sb = new StringBuilder(n / 2);
        for (int i = 0; i < n; i += 2) {
            char a = s.charAt(i);
            char b = s.charAt(i + 1);
            if (!(a == 0 && b == 0)) {
                sb.append((char) ((hexToInt(a) << 4) | hexToInt(b)));
            }
        }
        return sb.toString();
    }

    /**
     * Convert character to decimal
     *
     * @param ch : character  to convert
     * @return value of character in decimal
     */
    public int hexToInt(char ch) {
        if ('a' <= ch && ch <= 'f') {
            return ch - 'a' + 10;
        }
        if ('A' <= ch && ch <= 'F') {
            return ch - 'A' + 10;
        }
        if ('0' <= ch && ch <= '9') {
            return ch - '0';
        }
        return 0;
    }

    /**
     * Convert ascii string  to a hexadecimal string
     *
     * @param arg : ascii string to convert
     * @return hexadecimal string
     */
    public String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes(Charset.defaultCharset())));
    }


    /**
     * NOT
     *
     * @param x : bit to convert
     * @return : not(x)
     */
    private String not(String x) {
        if (x.equals("0")) {
            return "1";
        } else {
            return "0";
        }
    }

    /**
     * For Activities which want to treat new Intents as Intents with a new Tag attached. If the given Intent has a Tag extra, the Tag and UID will be
     * updated. This method will also check if the device/tag supports Mifare Classic (see return values).
     *
     * @param intent The Intent which should be checked for a new Tag.
     * @return <ul>
     *         <li>1 - The device/tag supports Mifare Classic</li>
     *         <li>0 - The device/tag does not support Mifare Classic</li>
     *         <li>-1 - Wrong Intent (action is not "ACTION_TECH_DISCOVERED").</li>
     *         </ul>
     */
public int treatAsNewTag(Intent intent) {
        return Common.treatAsNewTag(intent, null);

    }

    /**
     * Convert a string of hex data into a byte array. Original author is: Dave L. (http://stackoverflow.com/a/140861).
     *
     * @param hexString The hex string to convert
     * @return An array of bytes with the values of the string.
     */
    public byte[] hexStringToByteArray(String hexString) {
        return Common.hexStringToByteArray(hexString);
    }

    /**
     * Get information of AccessBits
     *
     * @param i : index of Accessbits
     * @return information
     */
    public String GetStringInfo(int i) {
        switch (i) {
            case 1:
                return "Read Write Increment Decrement with key A or B";
            case 2:
                return "Read with key A or B";
            case 3:
                return "Read with key A or B and Write with key B only";
            case 4:
                return "Read Write Increment Decrement with B and read + decrement with key A";
            case 5:
                return "Read Decrement with key A or B";
            case 6:
                return "Read Write with key B";
            case 7:
                return "Read with key B";
            case 8:
                return "Nothing";
            case 9:
                return "Write KEY A, read acces Bits, read KEY B and write KEY B only with KEY A";
            case 10:
                return "Read Acces Bits and Read Key B oncly with KEY A";
            case 11:
                return "Write KEY A, read Acces Bits and Write KEY B with key B or B AND read Access bits with KEY A";
            case 12:
                return "Read Acces bits with KEY A or KEY B";
            case 13:
                return "Write KEY A and B, Read/Write Acces bits and read KEY B with KEY A";
            case 14:
                return "Write KEY A and B, Read/Write Acces bits with KEY B and read Acces Bits with KEY A too";
            case 15:
                return "Read/Write Acces Bits with KEY B and read Acces Bits with KEY A too";
            case 16:
                return "Read Acces Bits with KEY A or B";
            default:
                return "Erreur index";
        }

    }

    public boolean isAuthorizationToWriteInSectorTrailer() {
        return AUTHORIZATION_TO_WRITE_IN_SECTOR_TRAILER;
    }

    public void setAuthorizationToWriteInSectorTrailer(boolean authorization) {
        AUTHORIZATION_TO_WRITE_IN_SECTOR_TRAILER = authorization;
    }

}