function permuted_x = partial_bit_reversal_permutation(c, x) 
    pos = zeros(1, 2^c);
    for i = 1:2^c 
        pos(i) = partial_bit_reversal(2^c, c, i) + 1;
    end
    permuted_x = x(pos);
end 


