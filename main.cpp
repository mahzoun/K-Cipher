#include "KCipher.h"
#include <iostream>
#include <cmath>
#include <givaro/gfq.h>
#include <givaro/givpower.h>
#include <givaro/givtimer.h>

using namespace std;
using namespace Givaro;

int main(int argc, char** argv)
{

    long p = (argc>1?atoi(argv[1]):5);
    long e = (argc>2?atoi(argv[2]):3);
    GFqDom<long> GFq(p, e);
    GFqDom<long> PrimeField(p,1);
    std::cout << "Working in GF(" << p << '^' << e << ')' << std::endl;
    std::cout << "Elements are polynomials in X modulo " << p << std::endl;

    Poly1Dom< GFqDom<long>, Dense > Pdom( PrimeField, Indeter("X") );

    // First get the irreducible polynomial irred
    // via irred = X^e - mQ
    // and X^e = X^(e-1) * X
    GFqDom<long>::Element temo, t, tmp;
    Poly1Dom< GFqDom<long>, Dense >::Element G, H, J, mQ, irred, modP;

    Pdom.init(G, Degree(GFq.exponent()-1)); // X^(e-1)
    GFq.init(temo,G); // internal representation

    Pdom.init(H, Degree(1) ); // X
    GFq.init(t,H); // internal representation

    GFq.init(tmp);

    GFq.mul(tmp, temo, t); // internal representation of X^e
    GFq.negin(tmp);        // internal representation of -X^e, i.e. of the irreducible polynomial without the largest monomial, X^e

    long lowerpart;
    // p-adic value of the lower part of the irreducible polynomial
    GFq.convert(lowerpart, tmp);
    std::cout << ' ' << p << "-adic value of the lower part of the irreducible : " << lowerpart << std::endl;

    long ptoe = power(p,e); // p-adic value of X^e
    std::cout << ' ' << p << '^' << e << " is : " << ptoe << std::endl;

    std::cout << " --> Computed irreducible: " << ptoe+lowerpart << std::endl;
    std::cout << "Stored        irreducible: " << GFq.irreducible() << std::endl;

    Poly1PadicDom< GFqDom<long>, Dense > PAD(Pdom);
    Poly1PadicDom< GFqDom<long>, Dense >::Element Polynomial;

    PAD.radix(Polynomial, GFq.irreducible());

    std::cout << "Irreducible polynomial coefficients: ";
    for(Poly1PadicDom< GFqDom<long>, Dense >::Element::iterator it = Polynomial.begin(); it != Polynomial.end(); ++it)
        PrimeField.write(std::cout << ' ', *it);
    std::cout << std::endl;


    PAD.write(std::cout << "The latter " << GFq.irreducible() << " represents: ", Polynomial)
            << " in " << p << "-adic"
            << std::endl;



    return 0;

}
