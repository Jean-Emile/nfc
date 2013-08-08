package org.kevoree.android.nfc.api;


import android.content.Intent;
import org.kevoree.android.nfc.impl.TagActionException;

public interface INfc {

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
    public boolean writeInABlock(int sector, int block, String data, byte[] key, boolean useAsKeyB) throws TagActionException;

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
    public boolean writeInASector(int sector, String data, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Write in all space of NFC Chip (752bytes for  MifareClassic 1K). For this, we need to have the same key for all sectors
     *
     * @param data : Data that we want to write(hexa)
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to write
     * @return true if data has been sent
     */
    public boolean writeInAllDataSpace(String data, byte[] key, boolean useAsKeyB)throws TagActionException;

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
    public boolean writeKeyA(int sector,  byte[] keyA, byte[] keyB, byte[] newKeyA) throws TagActionException;

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
    public boolean writeKeyB(int sector, byte[] keyA, byte[] keyB, byte[] newKeyB) throws TagActionException;

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
    public boolean writeAccessBit(int sector, byte[] keyA, byte[] keyB, byte[] newAccessBit) throws TagActionException;


    // ////////////////////////////////////////////////////////////

    // Read the NFC Chip

    // ////////////////////////////////////////////////////////////

    /**
     * Get ID of NFC TAG
     *
     * @return ID of TAG (String)
     */
    public String getId();

    /**
     * Get count of block of the NFC chip
     *
     * @return number of block of the NFC chip
     */
    public int getBlockCount();

    /**
     * Get count of block in a sector of the NFC chip
     *
     * @param sector : Sector whose we want to know the count of block
     * @return number of block in the sector of the NFC chip
     */
    public int getBlockCountInSector(int sector);

    /**
     * Get count of sector of the NFC chip
     *
     * @return number of sector of the NFC chip
     */
    public int getSectorCount();

    /**
     * Read a block of a sector of the nfc chip
     *
     * @param sector : Sector that we want to read
     * @param block : Block that we want to read
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to read
     * @return value of the block (hexadecimal)
     */
    public String readABlock(int sector, int block, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     *  Read a sector of the nfc chip
     *
     * @param sector : Sector that we want to read
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to read
     * @return value of the sector (hexadecimal)
     */
    public String readASector(int sector, byte[] key, boolean useAsKeyB)throws TagActionException;

    /**
     * Read all of the nfc chip.
     * For this, we need to have the same key for all sectors
     *
     * @param key : Key for the authentication
     * @param useAsKeyB : true if we use Key B to read
     * @return value of the NFC chip (hexadecimal)
     */
    public String readAllSpace(byte[] key, boolean useAsKeyB)throws TagActionException;

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
    public int getInfoForBlock(int sector, int block, byte[] key, boolean useAsKeyB)throws TagActionException;

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
    public int ReadAccessBits(byte c1, byte c2, byte c3, boolean isSectorTrailer);

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
    public byte[] createAccessBit(int permB0, int permB1, int permB2, int permSectorTrailer);

    /**
     * Convert hexadecimal string to an ascii string
     *
     * @param s : hexadecimal string to convert
     * @return ascii string
     */
    public String hexToAscii(String s);

    /**
     * Convert character to decimal
     *
     * @param ch : character  to convert
     * @return value of character in decimal
     */
    public int hexToInt(char ch);

    /**
     * Convert ascii string  to a hexadecimal string
     *
     * @param arg : ascii string to convert
     * @return hexadecimal string
     */
    public String toHex(String arg);


    /**
     * For Activities which want to treat new Intents as Intents with a new Tag attached. If the given Intent has a Tag extra, the Tag and
     * UID will be updated. This method will also check if the device/tag supports Mifare Classic (see return values).
     *
     * @param intent The Intent which should be checked for a new Tag.
     * @return <ul>
     *         <li>1 - The device/tag supports Mifare Classic</li>
     *         <li>0 - The device/tag does not support Mifare Classic</li>
     *         <li>-1 - Wrong Intent (action is not "ACTION_TECH_DISCOVERED").</li>
     *         </ul>
     */
    public int treatAsNewTag(Intent intent);

    /**
     * Convert a string of hex data into a byte array. Original author is: Dave L. (http://stackoverflow.com/a/140861).
     *
     * @param hexString The hex string to convert
     * @return An array of bytes with the values of the string.
     */
    public byte[] hexStringToByteArray(String hexString);
}
