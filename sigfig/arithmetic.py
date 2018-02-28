import sigfig as sf

def main():

    #r=multiply(Number("1.0021"),Number("12.12"))
    #out = r.round()
    #print r.value, out, r.sigfigs

    r=add(Number("1.0021"),Number("12.12"))
    out = r.round()
    print r.value, out, r.sigfigs

    #r=multiply(Number("307900"),Number("4.000"))
    #out = r.round()
    #print r.value, out, r.sigfigs

class Number:
    def __init__(self,n,sigfigs=None):

        if not isinstance(n,str):
            n=sf.ftos(n)

        self.value = float(n)
        self.svalue = n
        self.sigfigs = sigfigs\
            if sigfigs else sf.sigfigs(n)

        if "." not in self.svalue:
            self.dpoint = len(self.svalue)
        else:
            self.dpoint = self.svalue.index(".")

    def round(self):

        sig = self.sigfigs
        d = sf.sdigits(self.svalue)
        r = int(d[sig-1])
        c = int(d[sig])

        if c > 4:
            r+=1

        if self.dpoint > sig:
            return d[:sig-1]+str(r)+"0"*(self.dpoint-sig)

        return d[:self.dpoint]+"."+d[self.dpoint:sig-1]+str(r)

def multiply(x,y):

    sf = min(x.sigfigs,y.sigfigs)
    return Number(x.value*y.value,sigfigs=sf)

def divide(x,y):

    sf = min(x.sigfigs,y.sigfigs)
    return Number(x.value/y.value,sigfigs=sf)

def add(x,y):

    sf = min(len(x.svalue[x.dpoint+1:]), len(y.svalue[y.dpoint+1:]))
    return Number(x.value+y.value,sigfigs=sf)


if __name__ == "__main__":
    main()
