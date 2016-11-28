package crypto.rc4.sender.models;

/**
 * Created by davinder on 27/10/16.
 * It represents a RC4 state.
 * It saves State vector, i,j and roundNumber at this particular state
 */
public class RC4State {

    private byte[] state;       //state vector
    private int i;
    private int j;
    private int roundNumber;       // round number for the RC4state

    public RC4State(byte[] state, int i, int j, int roundNumber) {
        this.state = state;
        this.i = i;
        this.j = j;
        this.roundNumber = roundNumber;
    }

    public byte[] getState() {
        return state;
    }

    public void setState(byte[] state) {
        this.state = state;
    }

    public int getI() {
        return i;
    }

    public void setI(int i) {
        this.i = i;
    }

    public int getJ() {
        return j;
    }

    public void setJ(int j) {
        this.j = j;
    }

    public int getRoundNumber() {
        return roundNumber;
    }

    public void setRoundNumber(int roundNumber) {
        this.roundNumber = roundNumber;
    }

    /**
     *
     * @return byte array in Hexadecimal form
     */
    public String getStateString(){
        StringBuilder sb = new StringBuilder();
        for (byte b : state) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }


    /**
     * Two states are same if in both RC4State, State Vector, i,j and roundNumber are same
     * @param obj RC4 state object with which we have to compare
     * @return true if both states are same
     */
    public boolean equals(RC4State obj) {
        return this.getStateString().equals(obj.getStateString()) &&
                this.i == obj.getI() &&
                this.j == obj.getJ() &&
                this.roundNumber == obj.getRoundNumber();
    }
}
