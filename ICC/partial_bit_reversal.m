function phi = partial_bit_reversal(n, c, i) 
    j     = de2bi(i, n);
    cLSBs = j(1:c);
    phi   = bi2de(flip(cLSBs));
end 

