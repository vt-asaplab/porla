function generator = find_generator(p)
    for g = 2:p-1
        r = true;
        for q = 2:p-1
            if mod(p-1, q) == 0 && mod(sym(g)^((p-1)/q), p) == 1
                r = false;
                break;
            end
        end
        if r == true 
            generator = g;
            break;
        end
    end
end


