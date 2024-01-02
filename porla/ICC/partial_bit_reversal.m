function phi = partial_bit_reversal(n, c, i) 
    j      = de2bi(i, n);
    cLSBs  = j(1:c);
    j(1:c) = flip(cLSBs);
    phi    = bi2de(j);
end 

