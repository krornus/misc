import periodic
from molecule import Molecule,Atom

AVAGADRO=6.022e23
LIGHT=2.998e8
PLANCK=6.626e-34
RYDBERG=2.178972e-18


def inv_rydberg(sym,n1,n2):
    return 1/rydberg(sym,n1,n2)

def rydberg(n1,n2,sym=1):
    return RYDBERG*sym**2*(1/float(n1**2) - 1/float(n2**2))

def percent_error(e,t):
    return (abs(e-t)/t)*100

def percent_yield(t,a):
    return float(a)/t

def binary_naming(s):
    m = Molecule(s)

    elements = [not x.metal for x in m.iterelements()]

    if all(elements):
        return binary_nonmetal(m)
    else:
        return binary_metal(m)

def binary_nonmetal(m):

    i = m.iterelements()
    first = i.next()
    second = i.next()

    if first.element.symbol == "H":
        return "Hydrogen " + second.element.symbol + "ide"

    fn = first.prefixed(first=True)
    sn = second.prefixed(ide=True)

    return fn+" "+sn

def binary_metal(m):

    i = m.iterelements()
    cat = i.next()
    an = i.next()

    if not cat.metal:
        cat,an = an,cat

    return cat.element.name+" "+an.suffixed()


def binary_abundance(e,i1,i2):

    # isotope1(p) + isotope2(q) = amu
    # p = q - 1

    # isotope1(p) + isotope2(1-p) = amu
    # isotope1(p) + isotope2-isotope2(p) = amu
    # p(isotope1 - isotope2) = amu - isotop2
    # p = (amu - isotope2)/(isotope1 - isotope2)
    amu = 0
    try:
        amu = e.mass()
    except AttributeError:
        e = Atom(e)
        amu = e.mass()

    p = (amu - i2)/(i1 - i2)
    q = 1-(amu - i2)/(i1 - i2)

    return p,q

def combustion(c,co2,h2o):

    mwater = Molecule("H2O")
    mco2 = Molecule("CO2")

    molswater = h2o/mwater.mass()
    molsh = molswater*2

    molsc = co2/mco2.mass()

    massh=Atom("H").mass()*molsh
    massc=Atom("C").mass()*molsc

    print "COMBUSTIONHC:",massh,massc

    om = compound-massh-massc
    molso = om/Atom("O").mass()

    div = min(molso,molsc,molsh)

    sc,sh,so = molsc/div,molsh/div,molso/div
    mc,mh,mo = 0,0,0
    eps = .1

    print sc,sh,so
    for m in range(1,10):
        if mc == 0 and check_whole(sc*m, eps):
            mc = m
        if mh == 0 and check_whole(sh*m, eps):
            mh = m
        if mo == 0 and check_whole(so*m, eps):
            mo = m

    m = lcm(mc,lcm(mh, mo))

    return sc*m,sh*m,so*m

def lcm(x, y):
    print x,y
    if x > y:
        z = x
    else:
        z = y

    while(True):
        if((z % x == 0) and (z % y == 0)):
            lcm = z
            break
        z += 1

    return lcm

def check_whole(f,e):
    return int(f) != int(f+e) or int(f) != int(f-e)


#
#m=Molecule("NaI")
#print m.mass()
#
#m=Molecule("Al2S3")
#print m.mass()
#
#m=Molecule("Na2CO3")
#print m.mass()*.596
#
#m=Molecule("Al(CN)3")
#print 203.0/m.mass()
#
#m=Molecule("Ca")
#print (157.0/m.mass())*AVAGADRO
#
#m=Molecule("CH3OH")
#div = AVAGADRO/9.66e24
#print m.mass()/div
#
#m=Molecule("Cl")
#print m.mass()/AVAGADRO
#
#print 41*4
#
#m=Molecule("N2O")
#print (0.215/m.mass())*2
#
#print 7.5*8*AVAGADRO
#
#m=Molecule("P2O5")
#mols = 0.280/m.mass()
#p = mols*2*AVAGADRO
#o = mols*5*AVAGADRO
#print p+o
#
#
#c=9.12e24*(3./8.)
#h=9.12e24-c
#
#cm=Molecule("C")
#hm=Molecule("H")
#
#molc=c/AVAGADRO
#molh=h/AVAGADRO
#
#print molc*cm.mass()+molh*hm.mass()
#
#m=Molecule("O7")
#wx = (54.9-33.6)/2
#mols = 33.6/m.mass()
#print mols
#print wx/mols
#
#
#mh=Molecule("H")
#mc=Molecule("C")
#mo=Molecule("O")
#
#h=3.25
#c=19.36
#o=77.39
#
#ph=h/mh.mass()
#pc=c/mc.mass()
#po=o/mo.mass()
#
#print ph,pc,po
#print ph/pc
#print po/pc
#print po/ph
#
#
#mh=Molecule("H")
#mc=Molecule("C")
#mo=Molecule("O")
#mn=Molecule("N")
#
#c=67.31
#h=6.978
#n=4.617
#o=21.10
#
#pc=c/mc.mass()
#ph=h/mh.mass()
#pn=n/mn.mass()
#po=o/mo.mass()
#
#print ph,pc,po,pn
#print ph/pc,"h/c"
#print pc/po,"c/o"
#print po/pn,"o/n"
#
#
#mh=Molecule("H")
#mc=Molecule("C")
#mo=Molecule("O")
#
#h=9.15
#c=54.53
#o=36.32
#
#ph=h/mh.mass()
#pc=c/mc.mass()
#po=o/mo.mass()
#
#print ph,pc,po
#print ph/pc,"H/C"
#print po/pc,"O/C"
#print po/ph,"O/H"
#
#print 132-(mh.mass()+mo.mass())
#
#
#m = Molecule("Mo2O3")
#
#mamt = m.percent("Mo")*16.43
#oamt = 19.72-mamt
#
#molm = mamt/Molecule("Mo").mass()
#molo = oamt/Molecule("O").mass()
#
#print mamt,oamt
#print molm,molo
#print molo/molm
#
#
#m = Molecule("(NH4)(CH2)2")
#m.print_elements()
#
#no = Molecule("NO")
#nh = Molecule("(NH3)4")
#n = Molecule("N")
#o2 = Molecule("O2")
#o = Molecule("O")
#
#print (1.50*nh.percent("N"))/n.mass()
#print (1.50*o2.percent("O"))/n.mass()
#
#0.088077169693*4*no.mass()
#
#mh=Molecule("H")
#mc=Molecule("C")
#
#c=89.92
#h=100-c
#
#ph=h/mh.mass()
#pc=c/mc.mass()
#
#print ph,pc
#
#div = min(ph,pc)
#
#ph=ph/div
#pc=pc/div
#
#print pc*3,ph*3
#
#m = Molecule("C3H4")
#print 120.2/m.mass()
#m = Molecule("C9H12")
#print m.mass()
#
##===============================================================================
## COMBUSTRION
##===============================================================================
#
#capacid = 0.450
#water = 0.418
#co2 = 1.023
#
#mwater = Molecule("H2O")
#mco2 = Molecule("CO2")
#
#molswater = water/mwater.mass()
#molsh = molswater*2
#
#molsc = co2/mco2.mass()*1
#
#print molsc,molsh
#
#massh=Atom("H").mass()*molsh
#massc=Atom("C").mass()*molsc
#
#om = capacid-massh-massc
#
#molso = om/Atom("O").mass()
#
#print molso,molsc,molsh
#
#div = min(molso,molsc,molsh)
#
#print molso/div,molsc/div,molsh/div
#
## 1,3,6
#m = Molecule("C3H6O")
#print 116.2/m.mass()
#m = Molecule("C6H12O")
#print m.mass()
#
#print "="*80
#
#compound = 1.2
#co2 = 2.086
#water = 1.134
#
#mwater = Molecule("H2O")
#mco2 = Molecule("CO2")
#
#molswater = water/mwater.mass()
#molsh = molswater*2
#
#molsc = co2/mco2.mass()
#
#massh=Atom("H").mass()*molsh
#massc=Atom("C").mass()*molsc
#
#print compound-massh-massc
#
#om = compound-massh-massc
#molso = om/Atom("O").mass()
#
##print molso,molsc,molsh
#
#div = min(molso,molsc,molsh)
#
#print molsc/div,molsh/div,molso/div
#print 2*molsc/div,molsh/div,molso/div
#
#print "="*80
#
#m = Molecule("C2H2")
#print m, m.percent("C")
#m = Molecule("CH4")
#print m, m.percent("C")
#m = Molecule("CH3F")
#print m, m.percent("C")
#m = Molecule("CO2")
#print m, m.percent("C")

#compound = 2.90
#co2 = 8.78
#water = 4.49
#
#mwater = Molecule("H2O")
#mco2 = Molecule("CO2")
#
#print mwater.mass()
#print water
#molswater = water/mwater.mass()
#print molswater
#molsh = molswater*2
#print molsh
#
#molsc = co2/mco2.mass()
#print "molc: ",molsc
#
#massh=Atom("H").mass()*molsh
#massc=Atom("C").mass()*molsc
#
#print massh
#print massc
#
#div = min(molsc,molsh)
#print 2*molsh/div
#
#
#compound = 8.00
#co2 = 18.8
#water = 5.14
#
#mwater = Molecule("H2O")
#mco2 = Molecule("CO2")
#
#molswater = water/mwater.mass()
#molsh = molswater*2
#
#molsc = co2/mco2.mass()
#
#massh=Atom("H").mass()*molsh
#massc=Atom("C").mass()*molsc
#
#print compound-massh-massc
#
#om = compound-massh-massc
#molso = om/Atom("O").mass()
#
#
#div = min(molso,molsc,molsh)
#
#print molsc/div,molsh/div,molso/div
#print combustion(8.00,18.8,5.14)


# ============== CHSO ====================

#compound = 32.149
#co2 = 52.271
#water = 23.444
#
#combustion(compound,co2,water)
#
#
#mwater = Molecule("H2O")
#mco2 = Molecule("CO2")
#
#molswater = water/mwater.mass()
#molsh = molswater*2
#
#molsc = co2/mco2.mass()
#
#massh=Atom("H").mass()*molsh
#massc=Atom("C").mass()*molsc
#
#print "OURS:",massh,massc
#
#hp,cp = massh/compound, massc/compound
#
#compound = 38.053
#so2 = 16.447
#
#mso2 = Molecule("SO2")
#
#molss = so2/mso2.mass()
#masss=Atom("S").mass()*molss
#
#sp = masss/compound
#
#compound = 32.149
#
#masso = compound - compound*hp - compound*cp - compound*sp
#
#molso = masso/Atom("O").mass()
#mols_s = mass_s_final/Atom("S").mass()
#
#print molso, mols_s, molsh, molsc
#
#div = min(molso, mols_s, molsh, molsc)
#
#print 2*molsc/div,2*molsh/div,2*mols_s/div,2*molso/div
#
# ============== CHSO ====================

#m = Molecule("I2")
#imols = (61.9/m.mass())*2
#print imols
#
#m2 = Molecule("NaI")
#print m2.mass()*imols
#
#print 73.1136847381/m2.mass()

#

#m = Molecule("C6H12O6")
#cmols = 63.0/m.mass()*6
#hmols = cmols*2
#

#Fe2O3 = Molecule("Fe2O3")
#Fe = Molecule("Fe")
#CO = Molecule("CO")
#C = Molecule("C")
#
#print (12.5/Fe.mass())/.5
#
#Mg = Molecule("Mg")
#
#print (122.2/Mg.mass())*Molecule("Mg(NO3)2").mass()*.422
#
## use coefficients for problem for solving 1/c1MV = 1/cMV
#
#
#m = Molecule("HClO4")
#m  = 70.5/m.mass()
#
#n = (100 * (1/1.67)) / 1000
#
#print m/n
#
#
## problem 12-5a
## 15.0 g / Molecule("H2O") * (1mol h2so4 / 2 mol h20) * (1L / .250mol)
#
## 0.0486(0.1) = 0.00486/.02 = .243
#
#
#
#print Molecule("Ba3(PO4)2").mass()
