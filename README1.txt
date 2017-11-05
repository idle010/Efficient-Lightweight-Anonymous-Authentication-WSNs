Synopsis
This project contains the implementation details of the proposed scheme in "An Efficient Lightweight Anonymous Authentication Protocol for Wireless Sensor Networks".

Environmental requirements
Programs can run under Windows, Linux, and Macs. 
Install Proverif 1.96, download Address: http://proverif.inria.fr/
No additional libraries are required. 
ProVerif is a command-line tool which can be executed using the syntax:
           ./proverif [options] hfilenamei

Code example

C:\Users\idle>E:

E:\>E:\proverif\proverif1.96\proverif.exe E:\proverif\proverif1.96\ours-IEEE.pv
Linear part:
Completing equations...
Completed equations:
Convergent part:
XOR(XOR(x_13,y_14),y_14) = x_13
Completing equations...
Completed equations:
XOR(XOR(x_13,y_14),y_14) = x_13
Process:
{1}new IDi: bitstring;
{2}new PWi: bitstring;
{3}new bi: bitstring;
{4}new Snj: bitstring;
{5}let Fi: bitstring = XOR(Ki,H3(IDi,PWi,bi)) in
{6}let V: bitstring = H1(Mod(Concat(Ki,H3(IDi,PWi,bi)),CVaule)) in
(
    {7}!
    {8}let xKi: bitstring = XOR(Fi,H3(IDi,PWi,bi)) in
    {9}if (xKi = Ki) then
    {10}let V': bitstring = H1(Mod(Concat(xKi,H3(IDi,PWi,bi)),CVaule)) in
    {11}if (V' = V) then
    {12}event beginGUparam(GWN);
    {13}new rA: nonce;
    {14}new T_57: timestamp;
    {15}let CTT1: bitstring = XOR(Concat(rA,Snj),H3(IDi,xKi,Kug)) in
    {16}let vv1: bitstring = H6(IDi,CTT1,xKi,PID,Kug,T_57) in
    {17}out(c1, (PID,CTT1,vv1,T_57,isFresh(T_57,true)));
    {18}in(c1, (CT3: bitstring,v4: bitstring));
    {19}let (xsk: bitstring,xPID0: bitstring) = XOR(CT3,H4(rA,PID,xKi,Kug)) in
    {20}let v'4: bitstring = H5(Snj,IDi,xsk,rA,xPID0) in
    {21}if (v'4 = v4) then
    {22}out(c1, H4(Snj,IDi,xPID0,xsk));
    {23}event endUGparam(user);
    {24}out(c1, encrypt(secretA,xsk))
) | (
    {25}!
    {26}in(c1, (gPID: bitstring,CT1: bitstring,v1: bitstring,T': timestamp,checkT: bool));

    {27}if (checkT = true) then
    {28}if (gPID = PID) then
    {29}let (rAg: bitstring,gSN: bitstring) = XOR(CT1,H3(IDi,Ki,Kug)) in
    {30}event beginUGparam(user);
    {31}let v'1: bitstring = H6(IDi,CT1,Ki,gPID,Kug,T') in
    {32}if ((v'1 = v1) && (gSN = Snj)) then
    {33}new sk: bitstring;
    {34}event beginSGparam(SN);
    {35}let CTT2: bitstring = XOR(Concat(sk,IDi),H3(Kgs,gSN,NSj)) in
    {36}let vv2: bitstring = H5(IDi,Snj,sk,Kgs,NSj) in
    {37}out(c2, (CTT2,vv2));
    {38}in(c2, v3: bitstring);
    {39}let v'3: bitstring = H4(Snj,IDi,sk,NSj) in
    {40}if (v'3 = v3) then
    {41}event endGSparam(GWN);
    {42}out(c2, encrypt(secretC,sk));
    {43}new PID0: bitstring;
    {44}let CTT3: bitstring = XOR(Concat(sk,PID0),H4(rAg,PID,Ki,Kug)) in
    {45}let vv4: bitstring = H5(Snj,IDi,sk,rAg,PID0) in
    {46}out(c1, (CTT3,vv4));
    {47}in(c1, v5: bitstring);
    {48}let v'5: bitstring = H4(Snj,IDi,PID0,sk) in
    {49}if (v'5 = v5) then
    {50}event endGUparam(GWN);
    {51}out(c1, encrypt(secretB,sk))
) | (
    {52}!
    {53}in(c2, (CT2: bitstring,v2: bitstring));
    {54}event beginGSparam(GWN);
    {55}let (skx: bitstring,xA2: bitstring) = XOR(CT2,H3(Kgs,Snj,NSj)) in
    {56}let v'2: bitstring = H5(xA2,Snj,skx,Kgs,NSj) in
    {57}if (v'2 = v2) then
    {58}out(c2, H4(Snj,xA2,skx,NSj));
    {59}event endSGparam(SN);
    {60}out(c2, encrypt(secretD,skx))
)

-- Query not attacker(secretA[]); not attacker(secretB[]); not attacker(secretC[]); not at
tacker(secretD[])
Completing...
Starting query not attacker(secretA[])
RESULT not attacker(secretA[]) is true.
Starting query not attacker(secretB[])
RESULT not attacker(secretB[]) is true.
Starting query not attacker(secretC[])
RESULT not attacker(secretC[]) is true.
Starting query not attacker(secretD[])
RESULT not attacker(secretD[]) is true.
-- Query inj-event(endSGparam(x_1530)) ==> inj-event(beginSGparam(x_1530))
Completing...
Starting query inj-event(endSGparam(x_1530)) ==> inj-event(beginSGparam(x_1530))
RESULT inj-event(endSGparam(x_1530)) ==> inj-event(beginSGparam(x_1530)) is true.
-- Query inj-event(endGSparam(x_2995)) ==> inj-event(beginGSparam(x_2995))
Completing...
Starting query inj-event(endGSparam(x_2995)) ==> inj-event(beginGSparam(x_2995))
RESULT inj-event(endGSparam(x_2995)) ==> inj-event(beginGSparam(x_2995)) is true.
-- Query inj-event(endGUparam(x_4433)) ==> inj-event(beginGUparam(x_4433))
Completing...
Starting query inj-event(endGUparam(x_4433)) ==> inj-event(beginGUparam(x_4433))
RESULT inj-event(endGUparam(x_4433)) ==> inj-event(beginGUparam(x_4433)) is true.
-- Query inj-event(endUGparam(x_5880)) ==> inj-event(beginUGparam(x_5880))
Completing...
Starting query inj-event(endUGparam(x_5880)) ==> inj-event(beginUGparam(x_5880))
RESULT inj-event(endUGparam(x_5880)) ==> inj-event(beginUGparam(x_5880)) is true.

E:\>