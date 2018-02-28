import periodic
import prefix
import metals
import re

def main():
    m = Molecule("(NH4)H2PO4")
    print m.elements



class Atom:
    def __init__(self,s,n=1):
        self.element = periodic.element(s)
        self.quantity = n
        self.metal = self.element.symbol in metals.metals

    def mass(self):
        return self.element.mass*self.quantity

    def __str__(self):
        amount = str(self.quantity) if self.quantity > 1 else ""
        return self.element.symbol + amount

    def prefixed(self,first=False,ide=False):
        name = self.element.name

        if ide:
            name = prefix.ide[self.element.symbol]

        if self.quantity <= 1 and first:
            return name

        name = name.lower()
        drop = name[0] in prefix.vowells
        pf = prefix.prefixes[self.quantity-1]

        if drop and (pf[-1] == "a" or pf[-1] == "o"):
            pf = pf[:-1]

        return pf + name

    def suffixed(self):
        return prefix.ide[self.element.symbol]

class MoleculeGroup:
    def __init__(self,m,n):
        self.molecule = m
        self.n = n

    def mass(self):
        return self.molecule.mass() * self.n

    def __str__(self):
        amount = str(self.n) if self.n > 1 else ""
        mg = "({}){}".format(str(self.molecule), amount)
        return mg

class Molecule:
    def __init__(self, atoms):

        if isinstance(atoms, str):
            self.atoms = MoleculeBuilder().from_string(atoms)
        else:
            self.atoms = atoms

        self.elements = {}

        for a in self.atoms:
            if isinstance(a,MoleculeGroup):
                self.add_elements(a.molecule, a.n)
            else:
                self.elements[a.element] = \
                    self.elements.get(a.element,0) + a.quantity

    def iterelements(self):
        for a in self.atoms:
            if isinstance(a,MoleculeGroup):
                for aa in a.molecule.iterelements():
                    yield aa
            else:
                yield a

    def print_elements(self):
        for k,v in self.elements.items():
            print k.symbol, v

    def __str__(self):
        molecule = ""
        for a in self.atoms:
            molecule += str(a)
        return molecule

    def add_atom(self, atom):
        self.atoms.append(atom)

    def add_elements(self, m, mul):
        for k,v in m.elements.items():
            self.elements[k] = self.elements.get(k,0) + v*mul

    def add_element(self, s, n=1):
        self.atoms.append(Atom(s,n))

    def mass(self):
        w = 0
        for atom in self.atoms:
            w += atom.mass()

        return w

    def percent(self, s):
        e = periodic.element(s)
        return (e.mass*self.elements[e])/self.mass()

class MoleculeBuilder:
    def __init__(self):
        self.element_re = re.compile("([A-Z][a-z]*)([0-9]*)")
        self.digit_re = re.compile("([0-9]+)")

    def from_string(self,s):
        self.molecule = s

        m = []


        while self.molecule:
            m.append(self.read_token())

        return m

    def read_token(self):

        if self.molecule.startswith("("):
            return self.parentheses()
        e = self.element_re.match(self.molecule)
        if e:
            return self.element(e)


    def parentheses(self):

        if not self.molecule.startswith("("):
            return None

        level = 0
        idx = 0

        for c in self.molecule:
            idx += 1
            if c == "(":
                level += 1
            elif c == ")":
                level -= 1
            if level == 0:
                break


        mul = 1

        inner = self.molecule[1:idx-1]
        self.molecule = self.molecule[idx:]

        d = self.digit_re.match(self.molecule)

        if d:
            self.molecule = self.molecule[d.end()+1:]
            mul = int(d.group(1))

        return MoleculeGroup(Molecule(inner), mul)


    def element(self, a):

        self.molecule = self.molecule[a.end():]
        mul = int(a.group(2) or 1)

        return Atom(a.group(1), mul)


if __name__ == "__main__":
    main()
