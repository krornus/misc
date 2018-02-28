def question1():

    eqs = [
        "(NH4)2SO4",
        "KNO3",
        "(NH4)H2PO4",
        "NH3",
        "(NH4)2HPO4",
        "NH4NO3",
    ]

    percents = {}

    for eq in eqs:
        m = Molecule(eq)
        percents[m] = m.percent("N")

    percents=sorted(percents.items(), key=lambda (a,b): (b,a), reverse=True)


    for m,p in percents:
        print m,p


#print binary_naming("K3N")
#print binary_naming("AlBr3")
#print binary_naming("CaS")
#print binary_naming("PCl5")

#m=Molecule("XeF4")
#print m.percent("Xe")*6.395,"g"

#print binary_abundance("B",10.0129,11.0093)

#print Molecule("H3C(CH3)2CHN4O2C4").mass()
#print Molecule("C3(HC)2(OH)2CHHOCHCH2NHCH3").mass()

#m=Molecule("H2O")
#created=3.10e2
#print m.percent("O")*created

#m = Molecule("CaF2")
#created = 145.
#print m.percent("F")*created

#m = Molecule("BrN3")
#print m.mass()
#
#m = Molecule("CCl2F2")
#print m.mass()

#m = Molecule("C12H22O11")
#print m.percent("C")
#print m.percent("H")
#print m.percent("O")

#m = Molecule("KClO4")
#print m.percent("K")
#print m.percent("Cl")
#print m.percent("O")
